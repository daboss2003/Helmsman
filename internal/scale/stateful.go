package scale

import "strings"

// statefulImages is a curated denylist of image families that are stateful /
// clustered (databases, brokers, coordination stores) — the C4 disqualifier. These
// are config-file/cert-binding apps (plan §7.4), NEVER scaling candidates: scaling a
// database replica risks data corruption, so enabling scaling for one is refused at
// the chokepoint regardless of operator attestation. The match is on the image
// repository component, so a private-registry/tag rename can't slip a known DB past.
var statefulImages = []string{
	"postgres", "postgis", "mysql", "mariadb", "percona", "cockroach", "yugabyte",
	"redis", "valkey", "keydb", "memcached",
	"mongo", "couchdb", "cassandra", "scylla", "elasticsearch", "opensearch", "clickhouse",
	"influxdb", "victoriametrics", "timescale", "neo4j", "rethinkdb",
	"rabbitmq", "kafka", "redpanda", "nats", "pulsar", "activemq", "zookeeper", "etcd", "consul", "vault",
	"minio", "seaweedfs", "garage",
}

// StatefulImage reports whether an image reference belongs to a known stateful /
// clustered family (C4). It strips the registry, tag, and digest, then matches the
// final repository path component against the denylist (so "ghcr.io/acme/postgres:16"
// and "postgres" both match, but "my-postgres-helper" does not).
func StatefulImage(image string) bool {
	ref := image
	// strip digest then tag
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndexByte(ref, ':'); i >= 0 && !strings.Contains(ref[i:], "/") {
		ref = ref[:i]
	}
	// last path component is the repository name
	if i := strings.LastIndexByte(ref, '/'); i >= 0 {
		ref = ref[i+1:]
	}
	ref = strings.ToLower(ref)
	for _, s := range statefulImages {
		if ref == s {
			return true
		}
	}
	return false
}
