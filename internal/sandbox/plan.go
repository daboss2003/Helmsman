package sandbox

import "strings"

// PlanResult is the STATIC analysis of a setup script (plan §7 setup/plan): a
// no-exec summary shown on the confirm screen so the operator sees what they are
// authorizing. It never runs anything; the findings are advisory (the jail is the
// real containment), surfacing intent the operator should eyeball.
type PlanResult struct {
	Bytes    int
	Lines    int
	Findings []string // advisory notes (e.g. "references the network")
}

// notable maps a lowercased needle to an advisory note.
var notable = []struct {
	needle string
	note   string
}{
	{"docker", "references docker (the jail has NO docker.sock — such calls will fail)"},
	{"curl", "attempts network access (the jail has NO network — egress is blocked)"},
	{"wget", "attempts network access (the jail has NO network — egress is blocked)"},
	{"127.0.0.1", "references loopback (no reach to 2375/2019/9000 from the jail)"},
	{"localhost", "references loopback (no reach to 2375/2019/9000 from the jail)"},
	{"/var/run/docker.sock", "references the docker socket (NOT mounted in the jail)"},
	{"sudo", "uses sudo (the jail drops all capabilities; this will fail)"},
	{":80", "references port 80 (an edge port; cannot be bound from the jail)"},
	{":443", "references port 443 (an edge port; cannot be bound from the jail)"},
}

// Plan statically analyzes a setup script. It performs NO execution.
func Plan(script string) PlanResult {
	res := PlanResult{Bytes: len(script)}
	low := strings.ToLower(script)
	res.Lines = strings.Count(script, "\n")
	if len(script) > 0 && !strings.HasSuffix(script, "\n") {
		res.Lines++
	}
	seen := map[string]bool{}
	for _, n := range notable {
		if strings.Contains(low, n.needle) && !seen[n.note] {
			res.Findings = append(res.Findings, n.note)
			seen[n.note] = true
		}
	}
	return res
}
