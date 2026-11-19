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
// A `range` or `with` rebinds the dot, so field references inside one are not
// checked: the check never reports a false unknown.
func unknownFields(src string, html bool) ([]string, error) {
	var tree *parse.Tree
	if html {
		t, err := template.New("t").Parse(src)
		if err != nil {
			return nil, err
		}
		tree = t.Tree
	} else {
		t, err := tmpltext.New("t").Parse(src)
		if err != nil {
			return nil, err
		}
		tree = t.Tree
	}
	if tree == nil || tree.Root == nil {
		return nil, nil
	}
	known := map[string]bool{}
	rt := reflect.TypeOf(TemplateData{})
	for i := 0; i < rt.NumField(); i++ {
		known[rt.Field(i).Name] = true
	}
	var out []string
	seen := map[string]bool{}
	var walk func(n parse.Node, topLevelDot bool)
	walk = func(n parse.Node, topLevelDot bool) {
		switch n := n.(type) {
		case *parse.ListNode:
			if n == nil {
				return
			}
			for _, c := range n.Nodes {
				walk(c, topLevelDot)
			}
		case *parse.ActionNode:
			walk(n.Pipe, topLevelDot)
		case *parse.IfNode:
			walk(n.Pipe, topLevelDot)
			walk(n.List, topLevelDot)
			if n.ElseList != nil {
				walk(n.ElseList, topLevelDot)
			}
		case *parse.RangeNode, *parse.WithNode:
			// The dot is rebound inside: skip rather than risk a false unknown.
		case *parse.TemplateNode:
			if n.Pipe != nil {
				walk(n.Pipe, topLevelDot)
			}
		case *parse.PipeNode:
			if n == nil {
				return
			}
			for _, c := range n.Cmds {
				walk(c, topLevelDot)
			}
		case *parse.CommandNode:
			for _, a := range n.Args {
				walk(a, topLevelDot)
			}
		case *parse.FieldNode:
			if topLevelDot && len(n.Ident) > 0 && !known[n.Ident[0]] && !seen[n.Ident[0]] {
				seen[n.Ident[0]] = true
				out = append(out, n.Ident[0])
			}
		case *parse.ChainNode:
			walk(n.Node, topLevelDot)
		}
	}
	walk(tree.Root, true)
	return out, nil
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
