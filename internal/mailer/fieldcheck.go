package mailer

import (
	"fmt"
	"html/template"
	"reflect"
	tmpltext "text/template"
	"text/template/parse"
)

// unknownFields returns the template's field references that TemplateData does not
// have, found by walking the parsed template rather than by executing it.
//
// Executing only reports an unknown field on the branch that runs. With sample data
// that leaves a field empty, `{{if .Timezone}}{{.Timezne}}{{end}}` renders cleanly
// at save time yet fails on every real send, where Timezone is set — and every
// send then silently falls back to the built-in. Checking the tree covers every
// branch, whatever data the sample holds.
//
// Scoping: `range` and `with` rebind the dot inside their body, so references in
// the body are not checked (the check never reports a false unknown). Their
// pipeline and their `else` branch still use the enclosing dot, and ARE checked.
// A named template invoked as `{{template "x" .}}` is checked with the invoker's
// dot; one invoked with any other argument is not, for the same reason.
func unknownFields(src string, html bool) ([]string, error) {
	var (
		tree  *parse.Tree
		defs  map[string]*parse.Tree
		known = map[string]bool{}
	)
	if html {
		t, err := template.New("t").Parse(src)
		if err != nil {
			return nil, err
		}
		tree = t.Tree
		defs = map[string]*parse.Tree{}
		for _, d := range t.Templates() {
			if d.Tree != nil {
				defs[d.Name()] = d.Tree
			}
		}
	} else {
		t, err := tmpltext.New("t").Parse(src)
		if err != nil {
			return nil, err
		}
		tree = t.Tree
		defs = map[string]*parse.Tree{}
		for _, d := range t.Templates() {
			if d.Tree != nil {
				defs[d.Name()] = d.Tree
			}
		}
	}
	if tree == nil || tree.Root == nil {
		return nil, nil
	}
	rt := reflect.TypeOf(TemplateData{})
	for i := 0; i < rt.NumField(); i++ {
		known[rt.Field(i).Name] = true
	}

	var out []string
	seenField := map[string]bool{}
	visited := map[string]bool{} // named templates already checked: stops recursion
	var walk func(n parse.Node, dotIsData bool)
	walk = func(n parse.Node, dotIsData bool) {
		switch n := n.(type) {
		case *parse.ListNode:
			if n == nil {
				return
			}
			for _, c := range n.Nodes {
				walk(c, dotIsData)
			}
		case *parse.ActionNode:
			walk(n.Pipe, dotIsData)
		case *parse.IfNode:
			walk(n.Pipe, dotIsData)
			walk(n.List, dotIsData)
			if n.ElseList != nil {
				walk(n.ElseList, dotIsData)
			}
		case *parse.RangeNode:
			walk(n.Pipe, dotIsData)
			// n.List rebinds the dot; n.ElseList does not.
			if n.ElseList != nil {
				walk(n.ElseList, dotIsData)
			}
		case *parse.WithNode:
			walk(n.Pipe, dotIsData)
			if n.ElseList != nil {
				walk(n.ElseList, dotIsData)
			}
		case *parse.TemplateNode:
			if n.Pipe != nil {
				walk(n.Pipe, dotIsData)
				if dotIsData && isBareDot(n.Pipe) && !visited[n.Name] {
					visited[n.Name] = true
					if d, ok := defs[n.Name]; ok && d.Root != nil {
						walk(d.Root, true)
					}
				}
			}
		case *parse.PipeNode:
			if n == nil {
				return
			}
			for _, c := range n.Cmds {
				walk(c, dotIsData)
			}
		case *parse.CommandNode:
			for _, a := range n.Args {
				walk(a, dotIsData)
			}
		case *parse.FieldNode:
			if dotIsData && len(n.Ident) > 0 && !known[n.Ident[0]] && !seenField[n.Ident[0]] {
				seenField[n.Ident[0]] = true
				out = append(out, n.Ident[0])
			}
		case *parse.ChainNode:
			walk(n.Node, dotIsData)
		}
	}
	walk(tree.Root, true)
	return out, nil
}

// isBareDot reports whether a pipeline is exactly `.`, i.e. the template is invoked
// with the same dot as its caller.
func isBareDot(p *parse.PipeNode) bool {
	if p == nil || len(p.Cmds) != 1 || len(p.Cmds[0].Args) != 1 {
		return false
	}
	_, ok := p.Cmds[0].Args[0].(*parse.DotNode)
	return ok
}

// checkFields applies unknownFields to a template's three parts and reports the
// first unknown variable in the wording html/template itself uses, which the admin
// API already turns into a readable hint.
func (t Template) checkFields() error {
	for _, part := range []struct {
		src  string
		html bool
	}{{t.Subject, false}, {t.HTML, true}, {t.Text, false}} {
		if part.src == "" {
			continue
		}
		bad, err := unknownFields(part.src, part.html)
		if err != nil {
			return err
		}
		if len(bad) > 0 {
			return fmt.Errorf("template: can't evaluate field %s in type mailer.TemplateData", bad[0])
		}
	}
	return nil
}
