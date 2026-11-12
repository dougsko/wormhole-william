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
	"github.com/dougsko/wormhole-william/wormhole"
	"github.com/klauspost/compress/zip"
	"github.com/spf13/cobra"
)

var (
	allocate   bool
	onlyText   bool
	acceptFile bool
	outputFile string
)

func recvCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:     "receive [OPTIONS] [CODE]...",
		Aliases: []string{"recv"},
		Short:   "Receive a text message, file, or directory...",
		Run:     recvAction,
	}

	cmd.Flags().BoolVarP(&verify, "verify", "v", false, "display verification string (and wait for approval)")
	cmd.Flags().BoolVar(&hideProgressBar, "hide-progress", false, "suppress progress-bar display")
	cmd.Flags().BoolVarP(&zeromode, "zeromode", "0", false, "enable no-code anything-goes mode")
	cmd.Flags().BoolVarP(&allocate, "allocate", "a", false, "allocate a fresh code (do not prompt for one)")
	cmd.Flags().BoolVarP(&onlyText, "only-text", "t", false, "refuse file transfers, only accept text transfers")
	cmd.Flags().BoolVar(&acceptFile, "accept-file", envBool("WORMHOLE_ACCEPT_FILE", false), "accept file transfer without asking (env WORMHOLE_ACCEPT_FILE)")
	cmd.Flags().StringVarP(&outputFile, "output-file", "o", "", "the file or directory to create (default: filename from sender)")

	cmd.ValidArgsFunction = recvCodeCompletion

	return &cmd
}

func recvAction(cmd *cobra.Command, args []string) {
	var (
		code string
		c    = newClient()
		ctx  = context.Background()
	)

	if zeromode {
		if len(args) > 0 {
			bail("Cannot combine -0/--zeromode with a code")
		}
		if allocate {
			bail("Cannot combine --allocate with -0/--zeromode")
		}
		code = "0-"
	} else if len(args) > 0 {
		code = args[0]
	} else if allocate {
		// handled below via ReceiveAllocated
	} else {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Enter receive wormhole code: ")

		line, err := reader.ReadString('\n')
		if err != nil {
			errf("Error reading from stdin: %s\n", err)
		}
		code = strings.TrimSpace(line)
	}

	if verify {
		c.VerifierOk = func(code string) bool {
			fmt.Printf("Verifier %s.\n", code)
			return true
		}
	}

	var msg *wormhole.IncomingMessage
	var err error
	if allocate {
		msg, _, err = c.ReceiveAllocated(ctx, func(code string) {
			fmt.Fprintf(os.Stderr, "Allocated code: %s\n", code)
			fmt.Fprintf(os.Stderr, "On the other computer, please run:\n")
			fmt.Fprintf(os.Stderr, "   wormhole-william send --code %s <filename>\n", code)
		})
	} else {
		msg, err = c.Receive(ctx, code)
	}
	if err != nil {
		log.Fatal(err)
	}

	if onlyText && msg.Type != wormhole.TransferText {
		msg.Reject()
		bail("refusing non-text transfer (--only-text)")
	}

	switch msg.Type {
	case wormhole.TransferText:
		_, err := io.Copy(os.Stdout, msg)
		if err != nil {
			log.Fatal(err)
		}

		_, err = os.Stdout.WriteString("\n")
		if err != nil {
			log.Fatal(err)
		}
	case wormhole.TransferFile:
		srcName, err := safeBaseName(msg.Name)
		if err != nil {
			msg.Reject()
			bail("Unsafe filename in transfer offer: %s", msg.Name)
		}

		destName := srcName
		if outputFile != "" {
			d := outputFile
			if st, err := os.Stat(d); err == nil && st.IsDir() {
				d = filepath.Join(d, srcName)
			}
			destName = d
		}

		if _, err := os.Stat(destName); err == nil {
			msg.Reject()
			bail("Error refusing to overwrite existing '%s'", destName)
		} else if !os.IsNotExist(err) {
			msg.Reject()
			bail("Error stat'ing existing '%s'", destName)
		} else {
			accept := acceptFile
			fmt.Printf("Receiving file (%s) into: %s\n", formatBytes(msg.TransferBytes64), destName)
			if !accept {
				reader := bufio.NewReader(os.Stdin)
				fmt.Print("ok? (y/N):")

				line, err := reader.ReadString('\n')
				if err != nil {
					errf("Error reading from stdin: %s\n", err)
				}
				line = strings.TrimSpace(line)
				accept = line == "y"
			}

			if !accept {
				msg.Reject()
				bail("transfer rejected")
			} else {
				f, err := ioutil.TempFile(filepath.Dir(destName), filepath.Base(destName)+".tmp")
				if err != nil {
					bail("Failed to create tempfile: %s", err)
				}

				proxyReader := pbProxyReader(msg, msg.TransferBytes64)

				_, err = io.Copy(f, proxyReader)
				if err != nil {
					os.Remove(f.Name())
					bail("Receive file error: %s", err)
				}

				proxyReader.Close()

				tmpName := f.Name()
				f.Close()

				err = os.Rename(tmpName, destName)
				if err != nil {
					bail("Rename %s to %s failed: %s", tmpName, destName, err)
				}
				fmt.Printf("Received file written to: %s\n", destName)
			}
		}
	case wormhole.TransferDirectory:
		wd, err := os.Getwd()
		if err != nil {
			bail("Failed to get working directory: %s", err)
		}

		dirBase, err := safeBaseName(msg.Name)
		if err != nil {
			msg.Reject()
			bail("Unsafe directory name in transfer offer: %s", msg.Name)
		}

		dirName := filepath.Join(wd, dirBase)
		if outputFile != "" {
			if filepath.IsAbs(outputFile) {
				dirName = filepath.Clean(outputFile)
			} else {
				dirName = filepath.Join(wd, outputFile)
			}
		}

		if _, err := os.Stat(dirName); err == nil {
			msg.Reject()
			bail("Error refusing to overwrite existing '%s'", dirName)
		} else if !os.IsNotExist(err) {
			msg.Reject()
			bail("Error stat'ing existing '%s'", dirName)
		} else {
			accept := acceptFile
			fmt.Printf("Receiving directory (%s) into: %s\n", formatBytes(msg.TransferBytes64), dirName)
			fmt.Printf("%d files, %s (uncompressed)\n", msg.FileCount, formatBytes(msg.UncompressedBytes64))
			if !accept {
				reader := bufio.NewReader(os.Stdin)
				fmt.Print("ok? (y/N):")

				line, err := reader.ReadString('\n')
				if err != nil {
					errf("Error reading from stdin: %s\n", err)
				}
				line = strings.TrimSpace(line)
				accept = line == "y"
			}

			if !accept {
				msg.Reject()
				bail("transfer rejected")
			} else {
				err = os.MkdirAll(dirName, 0777)
				if err != nil {
					bail("Mkdir error for %s: %s\n", dirBase, err)
				}

				tmpFile, err := ioutil.TempFile(wd, dirBase+".zip.tmp")
				if err != nil {
					bail("Failed to create tempfile: %s", err)
				}

				defer tmpFile.Close()
				defer os.Remove(tmpFile.Name())

				proxyReader := pbProxyReader(msg, msg.TransferBytes64)

				n, err := io.Copy(tmpFile, proxyReader)
				if err != nil {
					os.Remove(tmpFile.Name())
					bail("Receive file error: %s", err)
				}

				zr, err := zip.NewReader(tmpFile, n)
				if err != nil {
					bail("Read zip error: %s", err)
				}

				for _, zf := range zr.File {
					p, err := filepath.Abs(filepath.Join(dirName, zf.Name))
					if err != nil {
						bail("Failes to calculate file path ABS: %s", err)
					}

					if !zipPathContained(dirName, p) {
						bail("Dangerous filename detected: %s", zf.Name)
					}

					rc, err := zf.Open()
					if err != nil {
						bail("Failed to open file in zip: %s %s", zf.Name, err)
					}

					dir := filepath.Dir(p)
					err = os.MkdirAll(dir, 0777)
					if err != nil {
						bail("Failed to mkdirall %s: %s", dir, err)
					}

					f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, zf.Mode())
					if err != nil {
						bail("Failed to open %s: %s", p, err)
					}

					_, err = io.Copy(f, rc)
					if err != nil {
						bail("Failed to write to %s: %s", p, err)
					}

					err = f.Close()
					if err != nil {
						bail("Error closing %s: %s", p, err)
					}

					rc.Close()
				}

				proxyReader.Close()
				fmt.Fprintf(os.Stderr, "Directory written to: %s\n", dirName)
			}
		}
	}
}

func errf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg, args...)
	if !strings.HasSuffix("\n", msg) {
		fmt.Fprint(os.Stderr, "\n")
	}
}

func bail(msg string, args ...interface{}) {
	errf(msg, args...)
	os.Exit(1)
}

func formatBytes(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "kMGTPE"[exp])
}

type proxyReadCloser struct {
	*pb.Reader
	bar *pb.ProgressBar
}

func (p *proxyReadCloser) Close() error {
	p.bar.Finish()
	return nil
}

func pbProxyReader(r io.Reader, size int64) io.ReadCloser {
	if hideProgressBar {
		return ioutil.NopCloser(r)
	} else {
		progressBar := pb.Full.Start64(size)
		progressBar.Set(pb.Bytes, true)
		progressBar.Set(pb.SIBytesPrefix, true)
		proxyReader := progressBar.NewProxyReader(r)
		return &proxyReadCloser{
			Reader: proxyReader,
			bar:    progressBar,
		}
	}
}
