package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/daboss2003/Helmsman/internal/backup"
	"github.com/daboss2003/Helmsman/internal/config"
	"github.com/daboss2003/Helmsman/internal/store"
)

// cmdRestore restores Helmsman's database from an encrypted .hmbk backup archive. It
// is deliberately a CLI step (not a dashboard button): it REPLACES the live database,
// so it must run with the service stopped, and it needs the same master key the backup
// was made with. The archive is decrypted, validated by opening it (which also runs
// migrations + refuses a downgrade from a newer binary), and only then swapped in —
// the previous DB is kept aside as helmsman.db.pre-restore-<ts>.
func cmdRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	configPath := fs.String("config", config.DefaultPath, "path to config.yaml")
	from := fs.String("from", "", "path to the .hmbk backup archive")
	force := fs.Bool("force", false, "confirm the restore (it replaces the current database)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *from == "" {
		return fmt.Errorf("usage: helmsman restore --from <archive.hmbk> --force")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	key, err := config.DecodeKey(cfg.EncryptionKey)
	if err != nil {
		return fmt.Errorf("decode master key: %w", err)
	}

	dbPath := filepath.Join(cfg.DataDir, "helmsman.db")
	tmp := dbPath + ".restore-tmp"

	// 1. Decrypt the archive to a temp file.
	enc, err := os.Open(*from)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer enc.Close()
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := backup.Decrypt(out, enc, key); err != nil {
		out.Close()
		os.Remove(tmp)
		return fmt.Errorf("decrypt archive (wrong master key, or corrupt/tampered backup): %w", err)
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}

	// 2a. Reject anything that isn't actually a Helmsman database (a blank or foreign
	// SQLite file must NEVER be installed over the live DB — store.Open alone would
	// happily migrate a fresh/empty file, so check the real schema first, read-only).
	if _, err := store.Inspect(tmp); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("the archive is not a valid helmsman backup: %w", err)
	}
	// 2b. Open it too (also runs migrations + refuses a downgrade from a newer binary).
	vdb, err := store.Open(tmp)
	if err != nil {
		os.Remove(tmp)
		os.Remove(tmp + "-wal")
		os.Remove(tmp + "-shm")
		return fmt.Errorf("the archive is not a valid/compatible helmsman database: %w", err)
	}
	vdb.Close()
	os.Remove(tmp + "-wal")
	os.Remove(tmp + "-shm")

	if !*force {
		os.Remove(tmp)
		return fmt.Errorf("this REPLACES the current database at %s. Stop the service first, then re-run with --force", dbPath)
	}

	// 3. Swap: keep the current DB aside, clear its stale side files, move in the new one.
	if _, statErr := os.Stat(dbPath); statErr == nil {
		aside := fmt.Sprintf("%s.pre-restore-%d", dbPath, time.Now().Unix())
		if err := os.Rename(dbPath, aside); err != nil {
			os.Remove(tmp)
			return fmt.Errorf("set current db aside: %w", err)
		}
		fmt.Printf("previous database kept at %s\n", aside)
	}
	os.Remove(dbPath + "-wal")
	os.Remove(dbPath + "-shm")
	if err := os.Rename(tmp, dbPath); err != nil {
		return fmt.Errorf("install restored db: %w", err)
	}

	fmt.Printf("restored %s from %s\nstart Helmsman again: systemctl start helmsman\n", dbPath, *from)
	return nil
}
