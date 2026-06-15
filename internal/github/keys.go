package github

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// DeployKey is a freshly generated ed25519 keypair for one repository: the private
// half (OpenSSH PEM) Helmsman keeps encrypted and fetches with, and the public half
// (authorized_keys line) installed on the repo as a READ-ONLY deploy key.
type DeployKey struct {
	PrivatePEM string // OpenSSH "BEGIN OPENSSH PRIVATE KEY" PEM
	PublicLine string // "ssh-ed25519 AAAA... <comment>"
}

// GenerateDeployKey makes a new ed25519 deploy keypair. comment is a human label
// embedded in both halves (e.g. "helmsman:my-app"). ed25519 is small, fast, and the
// modern default — no key-size choices to get wrong.
func GenerateDeployKey(comment string) (DeployKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return DeployKey{}, err
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return DeployKey{}, fmt.Errorf("github: marshal private key: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return DeployKey{}, fmt.Errorf("github: marshal public key: %w", err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	if comment != "" {
		line += " " + comment
	}
	return DeployKey{
		PrivatePEM: string(pem.EncodeToMemory(block)),
		PublicLine: line,
	}, nil
}
