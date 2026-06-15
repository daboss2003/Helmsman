package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/helmsman/helmsman/internal/config"
	"github.com/helmsman/helmsman/internal/envimport"
	"github.com/helmsman/helmsman/internal/envstore"
	"github.com/helmsman/helmsman/internal/store"
)

// cmdSecret is the SSH-only secret/env surface (values never on argv).
func cmdSecret(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: helmsman secret import --slug <slug> --from <.env>")
	}
	switch args[0] {
	case "import":
		return cmdSecretImport(args[1:])
	default:
		return fmt.Errorf("unknown secret subcommand %q (try: import)", args[0])
	}
}

// cmdSecretImport runs the §7.9 env import-and-own: parse + classify + the literal
// HARD STOP, diff against the store, and ingest by-reference (the uploaded file is
// never the live file). A live-secret rotation / secret→plain downgrade needs an
// explicit --confirm-rotations (a higher-friction, separate confirm).
func cmdSecretImport(args []string) error {
	fs := flag.NewFlagSet("secret import", flag.ContinueOnError)
	configPath := fs.String("config", config.DefaultPath, "path to config.yaml")
	slug := fs.String("slug", "", "app slug to import into")
	from := fs.String("from", "", "path to the .env to import (values read from the file, never argv)")
	confirmRot := fs.Bool("confirm-rotations", false, "also apply live-secret rotations / secret→plain downgrades")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *slug == "" || *from == "" {
		return fmt.Errorf("usage: helmsman secret import --slug <slug> --from <.env> [--confirm-rotations]")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	db, err := store.Open(filepath.Join(cfg.DataDir, "helmsman.db"))
	if err != nil {
		return err
	}
	defer db.Close()
	if err := checkKeySentinel(cfg, db); err != nil {
		return err
	}
	cipher, err := openCipher(cfg)
	if err != nil {
		return err
	}

	raw, err := os.ReadFile(*from)
	if err != nil {
		return fmt.Errorf("read %s: %w", *from, err)
	}
	entries, err := envimport.Parse(raw) // parse + hygiene + classify (biased secret)
	if err != nil {
		return err
	}
	if err := envimport.ValidateForIngest(entries); err != nil {
		return err // the override-proof literal-secret HARD STOP
	}

	es := envstore.New(db, cipher)
	cur, _, err := es.Current(*slug)
	if err != nil {
		return err
	}
	curMap := map[string]envimport.Current{}
	for _, e := range cur {
		curMap[e.Key] = envimport.Current{Value: e.Value.Reveal(), Secret: e.Secret}
	}
	d := envimport.Diff(curMap, entries)

	rotating := map[string]bool{}
	for _, k := range d.Rotations {
		rotating[k] = true
	}
	if d.NeedsRotationConfirm() && !*confirmRot {
		fmt.Printf("import would rotate/downgrade these live secrets: %v\n", d.Rotations)
		fmt.Println("re-run with --confirm-rotations to apply them (other changes are still applied below)")
	}

	// Merge: start from current, apply imports — but skip rotations unless confirmed.
	merged := map[string]envstore.Entry{}
	for _, e := range cur {
		merged[e.Key] = e
	}
	applied := 0
	for _, e := range entries {
		if rotating[e.Key] && !*confirmRot {
			continue // held back for the separate rotation confirm
		}
		merged[e.Key] = envstore.Entry{Key: e.Key, Value: e.Value, Secret: e.Secret}
		applied++
	}
	out := make([]envstore.Entry, 0, len(merged))
	for _, e := range merged {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	if _, err := es.Save(context.Background(), *slug, out, "cli:secret-import"); err != nil {
		return err
	}

	fmt.Printf("imported into %q: %d added, %d changed, %d unchanged (%d applied)\n",
		*slug, len(d.Added), len(d.Changed), len(d.Unchanged), applied)
	fmt.Println("the live .env re-renders from the encrypted store on the next deploy; the imported file is not the live file")
	return nil
}
