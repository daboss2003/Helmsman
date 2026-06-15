package definition

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// maxDefBytes caps a definition file (a decode-bomb defence; a real def is small).
const maxDefBytes = 512 << 10

// Parse turns helmsman.yaml bytes into a validated, typed Definition. It is the
// parser-differential-resistant chokepoint (plan §7.7):
//   - reject YAML anchors, aliases, and merge keys (<<) — they let one parser see a
//     different document than another, smuggling a key past validation;
//   - reject duplicate keys (last-wins ambiguity);
//   - reject a SECOND YAML document;
//   - reject unknown keys (KnownFields — additionalProperties:false everywhere);
//   - exact apiVersion + kind + immutable-slug shape, fail-closed.
func Parse(raw []byte) (*Definition, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, errors.New("empty definition")
	}
	if len(raw) > maxDefBytes {
		return nil, fmt.Errorf("definition too large (%d bytes, max %d)", len(raw), maxDefBytes)
	}

	// Pass 1: parse to a Node (which PRESERVES anchors/aliases) and harden it. This
	// must run BEFORE the typed decode, which would silently resolve aliases.
	var node yaml.Node
	if err := yaml.Unmarshal(raw, &node); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}
	if err := harden(&node); err != nil {
		return nil, err
	}

	// Pass 2: typed decode with unknown-field rejection.
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var d Definition
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("definition rejected (unknown or mistyped field): %w", err)
	}
	// A second document is not allowed (a parser-differential / smuggle vector).
	if err := dec.Decode(new(yaml.Node)); err != io.EOF {
		return nil, errors.New("a helmsman.yaml must contain exactly one document")
	}

	if err := d.validateEnvelope(); err != nil {
		return nil, err
	}
	return &d, nil
}

// harden recursively rejects the YAML constructs that enable parser-differential
// attacks: anchors, aliases, merge keys, and duplicate mapping keys.
func harden(n *yaml.Node) error {
	if n.Kind == yaml.AliasNode {
		return errors.New("YAML aliases (*ref) are not allowed in a definition")
	}
	if n.Anchor != "" {
		return errors.New("YAML anchors (&ref) are not allowed in a definition")
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			key := n.Content[i]
			if key.Tag == "!!merge" || key.Value == "<<" {
				return errors.New("YAML merge keys (<<) are not allowed in a definition")
			}
			if seen[key.Value] {
				return fmt.Errorf("duplicate key %q in a definition", key.Value)
			}
			seen[key.Value] = true
		}
	}
	for _, c := range n.Content {
		if err := harden(c); err != nil {
			return err
		}
	}
	return nil
}

// Canonical re-marshals a definition to canonical YAML (stable field order from the
// struct) — what is written back to canonical.yaml on every successful apply, so the
// stored form is always Helmsman's typed render, never the operator's raw bytes.
func Canonical(d *Definition) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(d); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
