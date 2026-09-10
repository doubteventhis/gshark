// helpers for the comparison feature

package main

import (
	"fmt"
	"os"
	"strings"
)

// a single field from a compare template file
type CompareField struct {
	Name       string
	Value      string
	Compare    bool
	ExactMatch bool
}

// holds a parsed compare template for field diffing
type CompareTemplate struct {
	Protocol string
	Fields   []CompareField
}

// holds parsed compare templates
var compareTemplates []*CompareTemplate

// reads a gshark output file and parses it into one or more templates
func parseCompareFile(path string) ([]*CompareTemplate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	content := string(data)

	// Strip UTF-8 BOM if present.
	content = strings.TrimPrefix(content, "\xEF\xBB\xBF")
	lines := strings.Split(content, "\n")

	var templates []*CompareTemplate
	var current *CompareTemplate

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		clean := ansiRegex.ReplaceAllString(line, "")
		trimmed := strings.TrimSpace(clean)

		// parse header line (this is a field separator)
		if strings.HasPrefix(trimmed, "[") {
			if end := strings.Index(trimmed[1:], "]"); end >= 0 {

				// save previous template if it has fields
				if current != nil && len(current.Fields) > 0 {
					templates = append(templates, current)
				}
				current = &CompareTemplate{
					Protocol: strings.ToLower(strings.TrimSpace(trimmed[1 : 1+end])),
				}
				continue
			}
		}

		// field lines start with the tree symbols
		if !strings.HasPrefix(trimmed, "├─") && !strings.HasPrefix(trimmed, "└─") {
			continue
		}
		if current == nil {
			continue
		}

		// remove prefix
		fieldPart := trimmed
		for _, prefix := range []string{"├─ ", "└─ ", "├─", "└─"} {
			if strings.HasPrefix(fieldPart, prefix) {
				fieldPart = strings.TrimPrefix(fieldPart, prefix)
				break
			}
		}
		fieldPart = strings.TrimSpace(fieldPart)

		// split on first ": "
		sepIdx := strings.Index(fieldPart, ": ")
		if sepIdx < 0 {
			continue
		}

		// save field name and value. markers go in front of the field name
		//   *name: value    diff this field
		//   **name: value   require an exact value match
		name := fieldPart[:sepIdx]
		value := fieldPart[sepIdx+2:]

		cf := CompareField{Value: value}
		switch {
		case strings.HasPrefix(name, "**"):
			cf.Compare = true
			cf.ExactMatch = true
			cf.Name = strings.TrimSpace(strings.TrimPrefix(name, "**"))
		case strings.HasPrefix(name, "*"):
			cf.Compare = true
			cf.Name = strings.TrimSpace(strings.TrimPrefix(name, "*"))
		default:
			cf.Name = name
		}
		if cf.Name == "" {
			continue
		}
		current.Fields = append(current.Fields, cf)
	}

	// dont forget the last template
	if current != nil && len(current.Fields) > 0 {
		templates = append(templates, current)
	}

	// guard against invalid tamplates
	if len(templates) == 0 {
		return nil, fmt.Errorf("no valid templates found in compare file")
	}

	return templates, nil
}

// counts the fields marked for comparison across all templates
func countCompareFields(templates []*CompareTemplate) int {
	n := 0
	for _, tmpl := range templates {
		for _, f := range tmpl.Fields {
			if f.Compare {
				n++
			}
		}
	}
	return n
}

// compare-fields mode. checks if a packet contains at least one field we're comparing
func matchesCompareField(fields []FieldEntry, tmpl *CompareTemplate) bool {
	have := make(map[string]string)
	for _, f := range fields {
		have[f.Name] = f.Value
	}
	for _, tf := range tmpl.Fields {
		if !tf.Compare {
			continue
		}
		val, present := have[tf.Name]
		if !present {
			continue
		}
		if tf.ExactMatch && val != tf.Value {
			continue
		}
		return true
	}
	return false
}

// compare-frame mode. the frame's protocol must equal the template's, and every ** field (alignment key) must be present with an equal value. all other template fields are diffed 
func alignCompareFrame(proto string, fvals map[string][]string, tmpl *CompareTemplate) (bool, int) {
	if !strings.EqualFold(proto, tmpl.Protocol) {
		return false, 0
	}
	score := 0
	counted := make(map[string]bool)
	for _, tf := range tmpl.Fields {
		vals, present := fvals[tf.Name]
		if tf.ExactMatch && (!present || !containsValue(vals, tf.Value)) {
			return false, 0
		}
		if present && !counted[tf.Name] {
			score++
			counted[tf.Name] = true
		}
	}
	return true, score
}

func containsValue(vals []string, v string) bool {
	for _, x := range vals {
		if x == v {
			return true
		}
	}
	return false
}

// check whether a template block references any link/network/transpor layer field
func templateHasTransport(tmpl *CompareTemplate) bool {
	for _, tf := range tmpl.Fields {
		if isSkipLayerField(tf.Name) {
			return true
		}
	}
	return false
}
