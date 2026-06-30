package main

import "runtime/debug"

// Version is overridable at build time via -ldflags "-X main.Version=...".
var Version = "dev"

func versionString() string {
	v := Version
	if v == "dev" {
		if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			v = bi.Main.Version
		}
	}
	return "mooring " + v
}
