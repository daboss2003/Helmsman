package web

import (
	"testing"

	"github.com/daboss2003/Helmsman/internal/definition"
)

func TestDefHasCertBindings(t *testing.T) {
	none := &definition.Definition{}
	none.Spec.Compose.Services = map[string]definition.Service{"web": {Image: "nginx:1"}}
	if defHasCertBindings(none) {
		t.Error("no cert_bindings should be false")
	}
	with := &definition.Definition{}
	with.Spec.Compose.Services = map[string]definition.Service{
		"web":    {Image: "nginx:1"},
		"broker": {Image: "emqx:5", CertBindings: []definition.CertBinding{{Hostname: "mqtt.example.com", Mount: "/certs"}}},
	}
	if !defHasCertBindings(with) {
		t.Error("a service with cert_bindings should be true")
	}
}
