package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dougsko/wormhole-william/wormhole"

	"github.com/spf13/cobra"
)

// sshAppID is the application ID used by python's `wormhole ssh`
// subcommand. Using the same ID lets the two clients exchange keys.
const sshAppID = "lothar.com/wormhole/ssh-add"

var (
	sshCodeLength int
	sshUser       string
	sshKeyFile    string
	sshYes        bool
)

func sshCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ssh",
		Short: "Facilitate sending/receiving SSH public keys",
	}

	inviteCmd := &cobra.Command{
		Use:   "invite",
		Short: "Add a public-key to a ~/.ssh/authorized_keys file",
		Args:  cobra.NoArgs,
		Run:   func(cmd *cobra.Command, args []string) { sshInviteAction() },
	}
	inviteCmd.Flags().IntVarP(&sshCodeLength, "code-length", "c", 2, "length of code (in words)")
	inviteCmd.Flags().StringVarP(&sshUser, "user", "u", "", "add to USER's ~/.ssh/authorized_keys")

	acceptCmd := &cobra.Command{
		Use:   "accept [flags] CODE",
		Short: "Send your SSH public-key",
		Long:  "Send your SSH public-key.\n\nIn response to a 'wormhole ssh invite' this will send the public-key\nyou specify (if there's only one in ~/.ssh/* that will be sent).",
		Args:  cobra.ExactArgs(1),
		Run:   func(cmd *cobra.Command, args []string) { sshAcceptAction(args[0]) },
	}
	acceptCmd.Flags().StringVarP(&sshKeyFile, "key-file", "F", "", "public key file, or directory containing *.pub files (default ~/.ssh/)")
	acceptCmd.Flags().BoolVarP(&sshYes, "yes", "y", false, "skip confirmation prompt to send key")

	cmd.AddCommand(inviteCmd)
	cmd.AddCommand(acceptCmd)

	return cmd
}

// sshClient builds a client like newClient() but with the ssh appid.
func sshClient() wormhole.Client {
	c := newClient()
	c.AppID = sshAppID
	return c
}

// sshPaths resolves the home directory and .ssh directory for the given
// user ("" means the current user).
func sshPaths(username string) (string, string, error) {
	var home string
	if username == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return "", "", fmt.Errorf("can't determine home directory: %s", err)
		}
		home = h
	} else {
		u, err := user.Lookup(username)
		if err != nil {
			return "", "", fmt.Errorf("can't look up user %q: %s", username, err)
		}
		home = u.HomeDir
	}
	return home, filepath.Join(home, ".ssh"), nil
}

// pubkeyInfo parses a public key line into its kind, keyid (comment),
// and the full line.
func pubkeyInfo(pubkey string) (kind, keyid, line string, err error) {
	line = strings.TrimSpace(pubkey)
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return "", "", "", fmt.Errorf("not an SSH public key (expected at least kind and key)")
	}
	kind = parts[0]
	keyid = "unknown"
	if len(parts) > 2 {
		keyid = parts[2]
	}
	return kind, keyid, line, nil
}

func sshInviteAction() {
	_, sshPath, err := sshPaths(sshUser)
	if err != nil {
		bail("%s", err)
	}
	authKeyPath := filepath.Join(sshPath, "authorized_keys")

	if _, err := os.Stat(authKeyPath); err != nil {
		fmt.Printf("Note: '%s' not found; will be created\n", authKeyPath)
		if _, err := os.Stat(sshPath); err != nil {
			fmt.Printf("      '%s' doesn't exist either\n", sshPath)
		}
	} else {
		f, err := os.OpenFile(authKeyPath, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			bail("No write permission on '%s'", authKeyPath)
		}
		f.Close()
	}
	if _, err := os.Stat(sshPath); err != nil {
		if os.IsNotExist(err) {
			// Create ~/.ssh up front (python does it at append time, after
			// the transfer; doing it now avoids failing after the key has
			// already been received).
			if err := os.MkdirAll(sshPath, 0o700); err != nil {
				bail("Can't create '%s': %s", sshPath, err)
			}
		} else {
			bail("Can't stat '%s': %s", sshPath, err)
		}
	} else if st, err := os.Stat(sshPath); err == nil && !st.IsDir() {
		bail("'%s' is not a directory", sshPath)
	}
	if _, err := os.ReadDir(sshPath); err != nil {
		bail("Can't read '%s'", sshPath)
	}

	c := sshClient()
	c.PassPhraseComponentLength = sshCodeLength

	ctx := context.Background()
	msg, _, err := c.ReceiveAllocated(ctx, func(code string) {
		fmt.Printf("Now tell the other user to run:\n\n")
		fmt.Printf("wormhole ssh accept %s\n\n", code)
	})
	if err != nil {
		log.Fatal(err)
	}

	if msg.Type != wormhole.TransferText {
		msg.Reject()
		bail("expected a text message (SSH public key), got a file transfer instead")
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, msg)
	if err != nil {
		log.Fatal(err)
	}

	kind, keyid, line, err := pubkeyInfo(buf.String())
	if err != nil {
		bail("%s", err)
	}

	f, err := os.OpenFile(authKeyPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		bail("Can't open '%s': %s", authKeyPath, err)
	}
	if _, err := fmt.Fprintf(f, "%s\n", line); err != nil {
		f.Close()
		bail("Can't write to '%s': %s", authKeyPath, err)
	}
	f.Close()

	fmt.Printf("Appended key type='%s' id='%s' to '%s'\n", kind, keyid, authKeyPath)
}

// findPublicKey locates a public key to send. hint may be empty (use
// ~/.ssh/), a directory containing *.pub files, or a regular *.pub file.
func findPublicKey(hint string) (kind, keyid, pubkey string, err error) {
	dir := hint
	if dir == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return "", "", "", fmt.Errorf("can't determine home directory: %s", err)
		}
		dir = filepath.Join(h, ".ssh")
	}

	// a regular file is used as the key directly
	if st, statErr := os.Stat(dir); statErr == nil && !st.IsDir() {
		return readPubkey(dir)
	} else if statErr != nil {
		return "", "", "", fmt.Errorf("can't find '%s'", dir)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", "", "", fmt.Errorf("can't read '%s'", dir)
	}
	var pubkeys []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(e.Name(), ".pub") {
			pubkeys = append(pubkeys, e.Name())
		}
	}
	sort.Strings(pubkeys)

	switch len(pubkeys) {
	case 0:
		return "", "", "", fmt.Errorf("no public keys in '%s'", dir)
	case 1:
		return readPubkey(filepath.Join(dir, pubkeys[0]))
	default:
	}

	fmt.Print("Multiple public-keys found:\n")
	for i, name := range pubkeys {
		fmt.Printf("  %d: %s\n", i, name)
	}
	for {
		fmt.Print("Send which one? ")
		reader := stdinReader
		ans, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", "", "", fmt.Errorf("reading from stdin: %s", err)
		}
		var idx int
		_, scanErr := fmt.Sscanf(strings.TrimSpace(ans), "%d", &idx)
		if scanErr != nil || idx < 0 || idx >= len(pubkeys) {
			fmt.Printf("Not a valid choice (0-%d)\n", len(pubkeys)-1)
			if err == io.EOF {
				return "", "", "", fmt.Errorf("no valid selection")
			}
			continue
		}
		return readPubkey(filepath.Join(dir, pubkeys[idx]))
	}
}

func readPubkey(path string) (kind, keyid, pubkey string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", "", fmt.Errorf("can't read '%s': %s", path, err)
	}
	kind, keyid, line, err := pubkeyInfo(string(data))
	if err != nil {
		return "", "", "", fmt.Errorf("%s: %s", path, err)
	}
	return kind, keyid, line, nil
}

func sshAcceptAction(code string) {
	kind, keyid, pubkey, err := findPublicKey(sshKeyFile)
	if err != nil {
		bail("%s", err)
	}

	fmt.Printf("Sending public key type='%s' keyid='%s'\n", kind, keyid)
	if !sshYes {
		fmt.Printf("Really send public key '%s'? (y/N) ", keyid)
		reader := stdinReader
		line, err := reader.ReadString('\n')
		if err != nil {
			errf("error reading from stdin: %s", err)
		}
		answer := strings.ToLower(strings.TrimSpace(line))
		if answer != "y" && answer != "yes" {
			bail("Aborted!")
		}
	}

	c := sshClient()
	ctx := context.Background()
	_, status, err := c.SendText(ctx, pubkey, wormhole.WithCode(code))
	if err != nil {
		log.Fatal(err)
	}
	s := <-status
	if s.Error != nil {
		log.Fatalf("Send error: %s", s.Error)
	} else if !s.OK {
		log.Fatalf("Send not ok")
	}

	fmt.Println("Key sent.")
}
