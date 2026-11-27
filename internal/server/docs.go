package server

// The API reference at /docs is rendered once, at startup, from the embedded
// OpenAPI document: plain HTML styled by the app's own CSS, with no script.
// The renderer understands the subset of OpenAPI 3.1 that openapi.json uses
// (refs to components, objects, arrays, oneOf, enums and examples), and
// TestSpecMatchesRoutes keeps that document honest.

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

//go:embed openapi.json
var specJSON []byte

//go:embed docs.html.tmpl
var docsTemplate string

// --- OpenAPI subset ---

type kv[T any] struct {
	Key string
	Val T
}

// ordered is a JSON object decoded in document order, which matters for
// fields and endpoints in a reference.
type ordered[T any] []kv[T]

func (o *ordered[T]) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return fmt.Errorf("want a JSON object")
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		var v T
		if err := dec.Decode(&v); err != nil {
			return err
		}
		*o = append(*o, kv[T]{t.(string), v})
	}
	return nil
}

func (o ordered[T]) get(k string) (T, bool) {
	for _, e := range o {
		if e.Key == k {
			return e.Val, true
		}
	}
	var zero T
	return zero, false
}

// typeList is OpenAPI's "type", which may be one name or a list.
type typeList []string

func (t *typeList) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*t = typeList{one}
		return nil
	}
	return json.Unmarshal(b, (*[]string)(t))
}

type apiSpec struct {
	OpenAPI string `json:"openapi"`
	Info    struct {
		Title, Version, Summary, Description string
	} `json:"info"`
	Security   []map[string][]string                `json:"security"`
	Tags       []struct{ Name, Description string } `json:"tags"`
	Paths      ordered[ordered[*operation]]         `json:"paths"`
	Components struct {
		SecuritySchemes map[string]*struct{ Description string } `json:"securitySchemes"`
		Parameters      map[string]*parameter                    `json:"parameters"`
		Responses       map[string]*response                     `json:"responses"`
		Schemas         ordered[*schema]                         `json:"schemas"`
	} `json:"components"`
}

type operation struct {
	OperationID string                 `json:"operationId"`
	Tags        []string               `json:"tags"`
	Summary     string                 `json:"summary"`
	Description string                 `json:"description"`
	Parameters  []*parameter           `json:"parameters"`
	Responses   ordered[*response]     `json:"responses"`
	Security    *[]map[string][]string `json:"security"`
}

type parameter struct {
	Ref         string  `json:"$ref"`
	Name        string  `json:"name"`
	In          string  `json:"in"`
	Description string  `json:"description"`
	Required    bool    `json:"required"`
	Schema      *schema `json:"schema"`
	Example     any     `json:"example"`
}

type response struct {
	Ref         string `json:"$ref"`
	Description string `json:"description"`
	Content     ordered[*struct {
		Schema  *schema `json:"schema"`
		Example any     `json:"example"`
	}] `json:"content"`
}

type schema struct {
	Ref         string           `json:"$ref"`
	Type        typeList         `json:"type"`
	Format      string           `json:"format"`
	Description string           `json:"description"`
	Enum        []any            `json:"enum"`
	Example     any              `json:"example"`
	Default     any              `json:"default"`
	Minimum     *float64         `json:"minimum"`
	Maximum     *float64         `json:"maximum"`
	Properties  ordered[*schema] `json:"properties"`
	Required    []string         `json:"required"`
	Items       *schema          `json:"items"`
	OneOf       []*schema        `json:"oneOf"`
}

func parseSpec(b []byte) (*apiSpec, error) {
	var sp apiSpec
	if err := json.Unmarshal(b, &sp); err != nil {
		return nil, fmt.Errorf("openapi.json: %w", err)
	}
	return &sp, nil
}

func refName(ref, kind string) string {
	return strings.TrimPrefix(ref, "#/components/"+kind+"/")
}

func (sp *apiSpec) param(p *parameter) (*parameter, error) {
	if p.Ref == "" {
		return p, nil
	}
	if q := sp.Components.Parameters[refName(p.Ref, "parameters")]; q != nil {
		return q, nil
	}
	return nil, fmt.Errorf("unknown parameter %s", p.Ref)
}

func (sp *apiSpec) response(r *response) (*response, error) {
	if r.Ref == "" {
		return r, nil
	}
	if q := sp.Components.Responses[refName(r.Ref, "responses")]; q != nil {
		return q, nil
	}
	return nil, fmt.Errorf("unknown response %s", r.Ref)
}

func (sp *apiSpec) schema(s *schema) (*schema, error) {
	if s.Ref == "" {
		return s, nil
	}
	if q, ok := sp.Components.Schemas.get(refName(s.Ref, "schemas")); ok {
		return q, nil
	}
	return nil, fmt.Errorf("unknown schema %s", s.Ref)
}

// --- view model ---

type docPage struct {
	Title, Version, Summary, OpenAPI string
	Intro                            template.HTML
	Sections                         []docSection
	Groups                           []docGroup
	Models                           []docModel
}

type docSection struct {
	ID, Title string
	Body      template.HTML
}

type docGroup struct {
	ID, Name    string
	Description template.HTML
	Ops         []docOp
}

type docOp struct {
	ID, Method, Path, Summary string
	PathHTML, Description     template.HTML
	Auth, AuthNote            string
	Params                    []docField
	Responses                 []docResponse
	Request, Example          template.HTML
	ExampleCode               int
}

type docResponse struct {
	Code        int
	Status      string
	OK          bool
	Description template.HTML
	Type        template.HTML
}

type docModel struct {
	ID, Name    string
	Description template.HTML
	Fields      []docField
	Example     template.HTML
}

type docField struct {
	Name, In    string
	Type        template.HTML
	Required    bool
	Description template.HTML
	Meta        string
}

// renderDocs builds the reference page from the spec.
func renderDocs(sp *apiSpec) ([]byte, error) {
	p := docPage{Title: sp.Info.Title, Version: sp.Info.Version, Summary: sp.Info.Summary, OpenAPI: sp.OpenAPI}
	intro, sections := splitSections(sp.Info.Description)
	p.Intro = markdown(intro)
	for _, s := range sections {
		p.Sections = append(p.Sections, docSection{ID: slug(s[0]), Title: s[0], Body: markdown(s[1])})
	}

	for _, tag := range sp.Tags {
		g := docGroup{ID: "tag-" + slug(tag.Name), Name: tag.Name, Description: markdown(tag.Description)}
		for _, path := range sp.Paths {
			for _, m := range path.Val {
				if !slices.Contains(m.Val.Tags, tag.Name) {
					continue
				}
				op, err := sp.docOp(path.Key, m.Key, m.Val)
				if err != nil {
					return nil, fmt.Errorf("%s %s: %w", strings.ToUpper(m.Key), path.Key, err)
				}
				g.Ops = append(g.Ops, op)
			}
		}
		p.Groups = append(p.Groups, g)
	}

	for _, e := range sp.Components.Schemas {
		fields, err := sp.fields(e.Val)
		if err != nil {
			return nil, fmt.Errorf("schema %s: %w", e.Key, err)
		}
		ex, err := sp.example(e.Val, 0)
		if err != nil {
			return nil, err
		}
		p.Models = append(p.Models, docModel{
			ID: "model-" + e.Key, Name: e.Key, Description: markdown(e.Val.Description),
			Fields: fields, Example: highlightJSON(ex),
		})
	}

	t, err := template.New("docs").Parse(docsTemplate)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, p); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var pathParam = regexp.MustCompile(`\{[^}]+\}`)

func (sp *apiSpec) docOp(path, method string, o *operation) (docOp, error) {
	op := docOp{
		ID: o.OperationID, Method: strings.ToUpper(method), Path: path, Summary: o.Summary,
		Description: markdown(o.Description),
		PathHTML: template.HTML(pathParam.ReplaceAllStringFunc(html.EscapeString(path), func(s string) string {
			return `<span class="pp">` + s + `</span>`
		})),
	}
	if op.ID == "" {
		return op, fmt.Errorf("missing operationId")
	}

	sec := sp.Security
	if o.Security != nil {
		sec = *o.Security
	}
	var key, anon bool
	for _, req := range sec {
		if len(req) == 0 {
			anon = true
		}
		if _, ok := req["apiKey"]; ok {
			key = true
		}
	}
	switch {
	case key && anon:
		op.Auth, op.AuthNote = "API key optional", "Without a key, only public monitors are visible."
	case key:
		op.Auth = "API key required"
	default:
		op.Auth = "No authentication"
	}

	// The request sample uses each parameter's example.
	sample, query := path, []string{}
	for _, raw := range o.Parameters {
		prm, err := sp.param(raw)
		if err != nil {
			return op, err
		}
		f, err := sp.field(prm.Name, prm.Schema, prm.Required, prm.Description)
		if err != nil {
			return op, err
		}
		f.In = prm.In
		op.Params = append(op.Params, f)
		ex := plain(prm.Example)
		if prm.Example == nil {
			ex = plain(prm.Schema.Default)
		}
		switch prm.In {
		case "path":
			sample = strings.ReplaceAll(sample, "{"+prm.Name+"}", ex)
		case "query":
			query = append(query, prm.Name+"="+ex)
		}
	}
	if len(query) > 0 {
		sample += "?" + strings.Join(query, "&")
	}
	cmd := `curl "$BLIP_URL` + sample + `"`
	if key {
		cmd += ` \` + "\n" + `  -H "Authorization: Bearer $BLIP_KEY"`
	}
	op.Request = highlightShell(cmd)

	for _, e := range o.Responses {
		code, err := strconv.Atoi(e.Key)
		if err != nil {
			return op, fmt.Errorf("response %q: want a status code", e.Key)
		}
		r, err := sp.response(e.Val)
		if err != nil {
			return op, err
		}
		dr := docResponse{Code: code, Status: http.StatusText(code), OK: code < 400, Description: markdown(r.Description)}
		if len(r.Content) > 0 {
			ct := r.Content[0]
			if ct.Val.Schema != nil {
				dr.Type = sp.typeHTML(ct.Val.Schema)
			}
			if op.Example == "" && dr.OK {
				var ex any = ct.Val.Example
				if ex == nil && ct.Val.Schema != nil {
					if ex, err = sp.example(ct.Val.Schema, 0); err != nil {
						return op, err
					}
				}
				if s, ok := ex.(string); ok && ct.Key == "text/plain" {
					op.Example = template.HTML(html.EscapeString(s))
				} else {
					op.Example = highlightJSON(ex)
				}
				op.ExampleCode = code
			}
		}
		op.Responses = append(op.Responses, dr)
	}
	return op, nil
}

// fields lists an object schema's properties.
func (sp *apiSpec) fields(s *schema) ([]docField, error) {
	var out []docField
	for _, p := range s.Properties {
		f, err := sp.field(p.Key, p.Val, slices.Contains(s.Required, p.Key), p.Val.Description)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

func (sp *apiSpec) field(name string, s *schema, required bool, desc string) (docField, error) {
	if s == nil {
		return docField{}, fmt.Errorf("%s: missing schema", name)
	}
	if _, err := sp.schema(s); err != nil {
		return docField{}, err
	}
	f := docField{Name: name, Required: required, Type: sp.typeHTML(s), Description: markdown(desc)}
	var meta []string
	if s.Default != nil {
		meta = append(meta, "default "+plain(s.Default))
	}
	switch {
	case s.Minimum != nil && s.Maximum != nil:
		meta = append(meta, plain(*s.Minimum)+" to "+plain(*s.Maximum))
	case s.Minimum != nil:
		meta = append(meta, "at least "+plain(*s.Minimum))
	case s.Maximum != nil:
		meta = append(meta, "at most "+plain(*s.Maximum))
	}
	if len(s.Enum) > 0 {
		vals := make([]string, len(s.Enum))
		for i, v := range s.Enum {
			vals[i] = plain(v)
		}
		meta = append(meta, "one of "+strings.Join(vals, ", "))
	}
	f.Meta = strings.Join(meta, " · ")
	return f, nil
}

// typeHTML names a schema's type, linking component schemas to their model.
func (sp *apiSpec) typeHTML(s *schema) template.HTML {
	switch {
	case s.Ref != "":
		n := html.EscapeString(refName(s.Ref, "schemas"))
		return template.HTML(`<a href="#model-` + n + `">` + n + `</a>`)
	case len(s.OneOf) > 0:
		parts := make([]string, len(s.OneOf))
		for i, o := range s.OneOf {
			parts[i] = string(sp.typeHTML(o))
		}
		return template.HTML(strings.Join(parts, " | "))
	case slices.Contains(s.Type, "array") && s.Items != nil:
		return "array of " + sp.typeHTML(s.Items)
	}
	t := html.EscapeString(strings.Join(s.Type, " | "))
	if s.Format != "" {
		t += " (" + html.EscapeString(s.Format) + ")"
	}
	return template.HTML(t)
}

// example builds a sample value from the schema's examples, in field order.
func (sp *apiSpec) example(s *schema, depth int) (any, error) {
	if depth > 8 {
		return nil, fmt.Errorf("schema nests too deeply")
	}
	s, err := sp.schema(s)
	if err != nil {
		return nil, err
	}
	switch {
	case s.Example != nil:
		return s.Example, nil
	case len(s.OneOf) > 0:
		for _, o := range s.OneOf {
			if !slices.Equal(o.Type, typeList{"null"}) {
				return sp.example(o, depth+1)
			}
		}
		return nil, nil
	case len(s.Properties) > 0:
		obj := ordered[any]{}
		for _, p := range s.Properties {
			v, err := sp.example(p.Val, depth+1)
			if err != nil {
				return nil, err
			}
			obj = append(obj, kv[any]{p.Key, v})
		}
		return obj, nil
	case s.Items != nil:
		v, err := sp.example(s.Items, depth+1)
		return []any{v}, err
	case s.Default != nil:
		return s.Default, nil
	case slices.Contains(s.Type, "object"):
		return ordered[any]{}, nil
	case slices.Contains(s.Type, "string"):
		return "string", nil
	case slices.Contains(s.Type, "integer"), slices.Contains(s.Type, "number"):
		return 0, nil
	case slices.Contains(s.Type, "boolean"):
		return false, nil
	}
	return nil, nil
}

// --- formatting ---

// highlightJSON pretty-prints v as HTML with token classes for the stylesheet.
func highlightJSON(v any) template.HTML {
	var b strings.Builder
	writeJSON(&b, v, "")
	return template.HTML(b.String())
}

func span(class, text string) string {
	return `<span class="` + class + `">` + html.EscapeString(text) + `</span>`
}

func writeJSON(b *strings.Builder, v any, indent string) {
	inner := indent + "  "
	switch v := v.(type) {
	case map[string]any: // examples given inline in the spec
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		obj := ordered[any]{}
		for _, k := range keys {
			obj = append(obj, kv[any]{k, v[k]})
		}
		writeJSON(b, obj, indent)
	case ordered[any]:
		if len(v) == 0 {
			b.WriteString(span("j-p", "{}"))
			return
		}
		b.WriteString(span("j-p", "{") + "\n")
		for i, e := range v {
			key, _ := json.Marshal(e.Key)
			b.WriteString(inner + span("j-k", string(key)) + span("j-p", ": "))
			writeJSON(b, e.Val, inner)
			if i < len(v)-1 {
				b.WriteString(span("j-p", ","))
			}
			b.WriteString("\n")
		}
		b.WriteString(indent + span("j-p", "}"))
	case []any:
		if len(v) == 0 {
			b.WriteString(span("j-p", "[]"))
			return
		}
		b.WriteString(span("j-p", "[") + "\n")
		for i, e := range v {
			b.WriteString(inner)
			writeJSON(b, e, inner)
			if i < len(v)-1 {
				b.WriteString(span("j-p", ","))
			}
			b.WriteString("\n")
		}
		b.WriteString(indent + span("j-p", "]"))
	case string:
		s, _ := json.Marshal(v)
		b.WriteString(span("j-s", string(s)))
	case nil:
		b.WriteString(span("j-b", "null"))
	case bool:
		b.WriteString(span("j-b", strconv.FormatBool(v)))
	default:
		b.WriteString(span("j-n", plain(v)))
	}
}

// plain formats a JSON value without exponents, so Unix times read as such.
func plain(v any) string {
	if f, ok := v.(float64); ok {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	return fmt.Sprint(v)
}

var (
	shellToken = regexp.MustCompile(`"[^"]*"|\S+|\s+`)
	shellVar   = regexp.MustCompile(`\$[A-Z_]+`)
)

// highlightShell marks up a shell command: the program, flags and quoted
// strings, with $VARIABLES called out inside them.
func highlightShell(cmd string) template.HTML {
	var b strings.Builder
	first := true
	for _, line := range strings.SplitAfter(cmd, "\n") {
		for _, tok := range shellToken.FindAllString(line, -1) {
			switch {
			case strings.TrimSpace(tok) == "":
				b.WriteString(tok)
			case first:
				b.WriteString(span("sh-c", tok))
				first = false
			case strings.HasPrefix(tok, `"`):
				s := html.EscapeString(tok)
				s = shellVar.ReplaceAllString(s, `<span class="sh-v">$0</span>`)
				b.WriteString(`<span class="sh-s">` + s + `</span>`)
			case strings.HasPrefix(tok, "-"):
				b.WriteString(span("sh-f", tok))
			case tok == `\`:
				b.WriteString(span("sh-p", tok))
			default:
				b.WriteString(html.EscapeString(tok))
			}
		}
	}
	return template.HTML(b.String())
}

func slug(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.TrimSuffix(b.String(), "-")
}

// splitSections cuts Markdown at its "## " headings into the text before
// them and [title, body] pairs.
func splitSections(md string) (string, [][2]string) {
	var intro strings.Builder
	var out [][2]string
	for _, line := range strings.SplitAfter(md, "\n") {
		if t, ok := strings.CutPrefix(line, "## "); ok {
			out = append(out, [2]string{strings.TrimSpace(t), ""})
			continue
		}
		if len(out) == 0 {
			intro.WriteString(line)
		} else {
			out[len(out)-1][1] += line
		}
	}
	return intro.String(), out
}

var (
	mdBold = regexp.MustCompile(`\*\*(.+?)\*\*`)
	mdLink = regexp.MustCompile(`\[([^\]]+)\]\(((?:https?://|/|#)[^)\s]*)\)`)
)

// inline renders `code`, **bold** and [links](url) in one escaped line.
func inline(s string) string {
	parts := strings.Split(s, "`")
	for i, p := range parts {
		p = html.EscapeString(p)
		if i%2 == 1 && i < len(parts)-1 {
			parts[i] = "<code>" + p + "</code>"
			continue
		}
		p = mdBold.ReplaceAllString(p, "<strong>$1</strong>")
		parts[i] = mdLink.ReplaceAllString(p, `<a href="$2">$1</a>`)
	}
	return strings.Join(parts, "")
}

// markdown renders the small Markdown subset the spec's descriptions use:
// paragraphs, "- " lists, "### " headings and fenced code (json and sh are
// highlighted).
func markdown(src string) template.HTML {
	var b, para strings.Builder
	var list []string
	flush := func() {
		if para.Len() > 0 {
			b.WriteString("<p>" + inline(strings.TrimSpace(para.String())) + "</p>\n")
			para.Reset()
		}
		if len(list) > 0 {
			b.WriteString("<ul>")
			for _, li := range list {
				b.WriteString("<li>" + inline(li) + "</li>")
			}
			b.WriteString("</ul>\n")
			list = nil
		}
	}
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "```"):
			flush()
			lang := strings.TrimPrefix(trimmed, "```")
			var code []string
			for i++; i < len(lines) && strings.TrimSpace(lines[i]) != "```"; i++ {
				code = append(code, lines[i])
			}
			body := strings.Join(code, "\n")
			var out template.HTML
			var v ordered[any]
			switch {
			case lang == "json" && json.Unmarshal([]byte(body), &v) == nil:
				out = highlightJSON(v)
			case lang == "sh":
				out = highlightShell(body)
			default:
				out = template.HTML(html.EscapeString(body))
			}
			b.WriteString(`<pre class="code"><code>` + string(out) + "</code></pre>\n")
		case trimmed == "":
			flush()
		case strings.HasPrefix(trimmed, "### "):
			flush()
			b.WriteString("<h4>" + inline(strings.TrimPrefix(trimmed, "### ")) + "</h4>\n")
		case strings.HasPrefix(trimmed, "- "):
			if para.Len() > 0 {
				flush()
			}
			list = append(list, strings.TrimPrefix(trimmed, "- "))
		case len(list) > 0 && strings.HasPrefix(line, "  "): // a wrapped list item
			list[len(list)-1] += " " + trimmed
		default:
			if len(list) > 0 {
				flush()
			}
			para.WriteString(trimmed + " ")
		}
	}
	flush()
	return template.HTML(b.String())
}

// --- serving ---

func (s *Server) serveSpec(w http.ResponseWriter, r *http.Request) {
	// The document is public and carries no credentials, so any origin may read it.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	serveAsset(w, r, s.spec)
}

func (s *Server) serveDocs(w http.ResponseWriter, r *http.Request) { serveAsset(w, r, s.docs) }
