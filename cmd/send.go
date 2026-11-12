package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/cheggaaa/pb/v3"
	"github.com/dougsko/wormhole-william/rendezvous"
	"github.com/dougsko/wormhole-william/version"
	"github.com/dougsko/wormhole-william/wormhole"
	qrterminal "github.com/mdp/qrterminal/v3"
	"github.com/spf13/cobra"
)

var (
	codeLen          int
	codeFlag         string
	sendTextFlag     string
	showQRCode       bool
	zeromode         bool
	ignoreUnsendable bool
)

func sendCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "send [WHAT]",
		Short: "Send a text message, file, or directory...",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 {
				sendText()
				return
			} else if len(args) > 1 {
				bail("Too many arguments")
			}

			stat, err := os.Stat(args[0])
			if err != nil {
				bail("Failed to read %s: %s", args[0], err)
			}

			if stat.IsDir() {
				sendDir(args[0])
				return
			} else {
				sendFile(args[0])
				return
			}
		},
	}

	cmd.Flags().BoolVarP(&verify, "verify", "v", false, "display verification string (and wait for approval)")
	cmd.Flags().IntVarP(&codeLen, "code-length", "c", 0, "length of code (in bytes/words)")
	cmd.Flags().StringVar(&codeFlag, "code", "", "human-generated code phrase")
	cmd.Flags().StringVar(&sendTextFlag, "text", "", "text message to send, instead of a file.\nUse '-' to read from stdin")
	cmd.Flags().BoolVar(&hideProgressBar, "hide-progress", false, "suppress progress-bar display")
	cmd.Flags().BoolVar(&showQRCode, "qr", envBool("WORMHOLE_QR", true), "display code as QR code (use --no-qr to disable, or set WORMHOLE_QR=0)")
	cmd.Flags().BoolVarP(&zeromode, "zeromode", "0", false, "enable no-code anything-goes mode")
	cmd.Flags().BoolVar(&ignoreUnsendable, "ignore-unsendable-files", false, "don't raise an error if a file can't be read")

	return &cmd
}

func effectiveCode() string {
	if zeromode {
		if codeFlag != "" {
			bail("Cannot combine -0/--zeromode with --code")
		}
		return "0-"
	}
	return codeFlag
}

func newClient() wormhole.Client {
	th, err := transitHelperAddress(transitHelper)
	if err != nil {
		bail("%v", err)
	}

	url := relayURL
	if url == "" {
		url = wormhole.DefaultRendezvousURL
	}

	c := wormhole.Client{
		AppID:                     appID,
		RendezvousURL:             relayURL,
		TransitRelayAddress:       th,
		PassPhraseComponentLength: codeLen,
		NoListen:                  noListen,
		OnConnect: func(info rendezvous.ConnectInfo) {
			printWelcome(url, info)
		},
	}

	if verify {
		c.VerifierOk = func(code string) bool {
			reader := bufio.NewReader(os.Stdin)
			fmt.Printf("Verifier %s. ok? (yes/no): ", code)

			yn, _ := reader.ReadString('\n')
			yn = strings.TrimSpace(yn)

			return yn == "yes"
		}
	}

	return c
}

func printWelcome(url string, info rendezvous.ConnectInfo) {
	if info.MOTD != "" {
		fmt.Fprintf(os.Stderr, "Server (at %s) says:\n", url)
		for _, line := range strings.Split(strings.TrimRight(info.MOTD, "\n"), "\n") {
			fmt.Fprintf(os.Stderr, " %s\n", line)
		}
	}
	if info.CurrentCLIVersion != "" && info.CurrentCLIVersion != version.AgentVersion {
		fmt.Fprintf(os.Stderr, "Warning: errors may occur unless both sides are running the same version\n")
		fmt.Fprintf(os.Stderr, "Server claims %s is current, but ours is %s\n", info.CurrentCLIVersion, version.AgentVersion)
	}
}

func printInstructions(code string) {
	if zeromode {
		fmt.Fprintf(os.Stderr, "On the other computer, please run: wormhole-william receive -0 (or wormhole receive -0)\n")
		return
	}

	mwCmd := "wormhole receive"
	wwCmd := "wormhole-william recv"

	if verify {
		mwCmd = mwCmd + " --verify"
		wwCmd = wwCmd + " --verify"
	}

	fmt.Printf("On the other computer, please run: %s (or %s)\n", mwCmd, wwCmd)
	fmt.Printf("Wormhole code is: %s\n", code)

	if showQRCode {
		qrterminal.Generate(fmt.Sprintf("wormhole-transfer:%s", code), qrterminal.L, os.Stderr)
	}
}

func sendFile(filename string) {
	f, err := os.Open(filename)
	if err != nil {
		bail("Failed to open %s: %s", filename, err)
	}

	c := newClient()

	ctx := context.Background()

	var bar *pb.ProgressBar

	args := []wormhole.SendOption{
		wormhole.WithCode(effectiveCode()),
	}

	if !hideProgressBar {
		args = append(args, wormhole.WithProgress(func(sentBytes int64, totalBytes int64) {
			if bar == nil {
				bar = pb.Full.Start64(totalBytes)
				bar.Set(pb.Bytes, true)
				bar.Set(pb.SIBytesPrefix, true)
			}
			bar.SetCurrent(sentBytes)

			if sentBytes == totalBytes {
				bar.Finish()
			}
		}))
	}

	code, status, err := c.SendFile(ctx, filepath.Base(filename), f, args...)
	if err != nil {
		bail("Error sending message: %s", err)
	}

	printInstructions(code)

	s := <-status

	if s.OK {
		fmt.Println("file sent")
	} else {
		bail("Send error: %s", s.Error)
	}
}

func sendDir(dirpath string) {
	dirpath = strings.TrimSuffix(dirpath, "/")

	stat, err := os.Stat(dirpath)
	if err != nil {
		log.Fatal(err)
	}

	if !stat.IsDir() {
		log.Fatalf("%s is not a directory", dirpath)
	}

	prefix, dirname := filepath.Split(dirpath)

	var entries []wormhole.DirectoryEntry

	filepath.Walk(dirpath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if ignoreUnsendable {
				fmt.Fprintf(os.Stderr, "Skipping unsendable file %s: %s\n", path, err)
				return nil
			}
			bail("Error walking %s: %s", path, err)
		}

		if info.IsDir() {
			return nil
		}

		if !info.Mode().IsRegular() {
			return nil
		}

		// probe readability now so we fail (or skip) before the transfer starts
		probe, err := os.Open(path)
		if err != nil {
			if ignoreUnsendable {
				fmt.Fprintf(os.Stderr, "Skipping unsendable file %s: %s\n", path, err)
				return nil
			}
			bail("Cannot read %s: %s", path, err)
		}
		probe.Close()

		relPath := strings.TrimPrefix(path, prefix)

		entries = append(entries, wormhole.DirectoryEntry{
			Path: relPath,
			Mode: info.Mode(),
			Reader: func() (io.ReadCloser, error) {
				return os.Open(path)
			},
		})

		return nil
	})

	c := newClient()

	ctx := context.Background()
	code, status, err := c.SendDirectory(ctx, dirname, entries, wormhole.WithCode(effectiveCode()))
	if err != nil {
		log.Fatal(err)
	}

	printInstructions(code)

	s := <-status

	if s.OK {
		fmt.Println("directory sent")
	} else {
		bail("Send error: %s", s.Error)
	}
}

func sendText() {
	c := newClient()

	var msg string
	if sendTextFlag == "-" {
		data, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			bail("Read stdin err: %s", err)
		}
		msg = string(data)
	} else if sendTextFlag != "" {
		msg = sendTextFlag
	} else {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Text to send: ")
		msg, _ = reader.ReadString('\n')
		msg = strings.TrimSpace(msg)
	}

	ctx := context.Background()
	code, status, err := c.SendText(ctx, msg, wormhole.WithCode(effectiveCode()))
	if err != nil {
		log.Fatal(err)
	}

	printInstructions(code)

	s := <-status

	if s.Error != nil {
		log.Fatalf("Send error: %s", s.Error)
	} else if s.OK {
		fmt.Println("text message sent")
	} else {
		log.Fatalf("Hmm not ok but also not error")
	}
}
