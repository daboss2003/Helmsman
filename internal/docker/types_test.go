package docker

import (
	"encoding/json"
	"reflect"
	"testing"
)

// IPs() unmarshals /containers/json's NetworkSettings, returns non-empty IPs sorted
// by network name (deterministic), and copes with empty IPs / no networks.
func TestContainerIPs(t *testing.T) {
	cases := []struct {
		name string
		json string
		want []string
	}{
		{
			name: "sorted by network name, empties dropped",
			// zeta_net sorts after alpha_net, so alpha's IP comes first; mid_net has no IP.
			json: `{"NetworkSettings":{"Networks":{
				"zeta_net":{"IPAddress":"172.18.0.9"},
				"alpha_net":{"IPAddress":"172.19.0.3"},
				"mid_net":{"IPAddress":""}}}}`,
			want: []string{"172.19.0.3", "172.18.0.9"},
		},
		{name: "no networks", json: `{"NetworkSettings":{"Networks":{}}}`, want: nil},
		{name: "absent NetworkSettings", json: `{"Id":"x"}`, want: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c Container
			if err := json.Unmarshal([]byte(tc.json), &c); err != nil {
				t.Fatal(err)
			}
			if got := c.IPs(); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("IPs() = %v, want %v", got, tc.want)
			}
		})
	}
}
