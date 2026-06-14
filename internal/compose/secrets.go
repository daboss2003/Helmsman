package compose

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// FileSecret is a compose top-level file-mounted secret (a TLS keypair, a
// credential file). Helmsman shows these as present/missing by stat only and
// NEVER reads their contents (plan §7 file-secrets vs env).
type FileSecret struct {
	Name string
	Path string
}

// FileSecrets extracts top-level `secrets:` entries that have a `file:` path.
// It is read-only and best-effort: a malformed document yields no secrets rather
// than an error (the validator is the gate; this is just for the panel).
func FileSecrets(raw []byte, env Env) []FileSecret {
	resolved := Interpolate(string(raw), env)
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(resolved), &doc); err != nil || len(doc.Content) == 0 {
		return nil
	}
	resolveAliases(&doc, 0)
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil
	}
	var secretsNode *yaml.Node
	for _, kv := range pairs(root) {
		if kv.key.Value == "secrets" {
			secretsNode = kv.val
		}
	}
	if secretsNode == nil || secretsNode.Kind != yaml.MappingNode {
		return nil
	}
	var out []FileSecret
	for _, entry := range pairs(secretsNode) {
		if entry.val.Kind != yaml.MappingNode {
			continue
		}
		for _, f := range pairs(entry.val) {
			if f.key.Value == "file" && f.val.Kind == yaml.ScalarNode && strings.TrimSpace(f.val.Value) != "" {
				out = append(out, FileSecret{Name: entry.key.Value, Path: f.val.Value})
			}
		}
	}
	return out
}
