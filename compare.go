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

		// save field name and value
		name := fieldPart[:sepIdx]
		value := fieldPart[sepIdx+2:]

		cf := CompareField{Name: name}

		// check for exact match fields
		if strings.HasSuffix(value, "**") {
			cf.Compare = true
			cf.ExactMatch = true
			cf.Value = strings.TrimSuffix(value, "**")

		// check for fields to compare
		} else if strings.HasSuffix(value, "*") {
			cf.Compare = true
			cf.Value = strings.TrimSuffix(value, "*")

		// save other fields in template
		} else {
			cf.Value = value
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

// compare-frame mode. checks packets for the specified protocol and fields
func matchesCompareFrame(proto string, fields []FieldEntry, tmpl *CompareTemplate) bool {
	if !strings.EqualFold(proto, tmpl.Protocol) {
		return false
	}
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
			return false
		}
		if tf.ExactMatch && val != tf.Value {
			return false
		}
	}
	return true
}
