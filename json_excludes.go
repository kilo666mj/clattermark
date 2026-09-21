package main

import (
	"encoding/json"
	"log"
	"regexp"
	"strings"
)

// JSONExcludeConfig describes a structured-noise rule. Field conditions apply
// to direct properties of the JSON object stored in the parsed text field.
type JSONExcludeConfig struct {
	Process          string          `json:"process"`
	BooleanFields    map[string]bool `json:"boolean_fields"`
	EmptyArrayFields []string        `json:"empty_array_fields"`
}

type jsonExclude struct {
	process          *regexp.Regexp
	booleanFields    map[string]bool
	emptyArrayFields []string
}

func compileJSONExcludes(configs []JSONExcludeConfig) []jsonExclude {
	compiled := make([]jsonExclude, 0, len(configs))
	for i, cfg := range configs {
		if strings.TrimSpace(cfg.Process) == "" {
			log.Printf("invalid structured JSON exclude %d: process regex is required", i)
			continue
		}
		if len(cfg.BooleanFields) == 0 && len(cfg.EmptyArrayFields) == 0 {
			log.Printf("invalid structured JSON exclude %d: at least one field condition is required", i)
			continue
		}
		process, err := regexp.Compile(cfg.Process)
		if err != nil {
			log.Printf("invalid structured JSON exclude process regex %q: %v", cfg.Process, err)
			continue
		}
		compiled = append(compiled, jsonExclude{
			process:          process,
			booleanFields:    cfg.BooleanFields,
			emptyArrayFields: append([]string(nil), cfg.EmptyArrayFields...),
		})
	}
	return compiled
}

func matchesJSONExclude(parsed map[string]string, excludes []jsonExclude) bool {
	if len(excludes) == 0 || parsed["process"] == "" || parsed["text"] == "" {
		return false
	}
	var object map[string]json.RawMessage
	decoded := false
	for _, exclude := range excludes {
		if !exclude.process.MatchString(parsed["process"]) {
			continue
		}
		if !decoded {
			if err := json.Unmarshal([]byte(parsed["text"]), &object); err != nil || object == nil {
				return false
			}
			decoded = true
		}
		if matchesJSONFields(object, exclude) {
			return true
		}
	}
	return false
}

func matchesJSONFields(object map[string]json.RawMessage, exclude jsonExclude) bool {
	for name, want := range exclude.booleanFields {
		raw, ok := object[name]
		if !ok {
			return false
		}
		var got bool
		if err := json.Unmarshal(raw, &got); err != nil || got != want {
			return false
		}
	}
	for _, name := range exclude.emptyArrayFields {
		raw, ok := object[name]
		if !ok {
			return false
		}
		var values []json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil || values == nil || len(values) != 0 {
			return false
		}
	}
	return true
}
