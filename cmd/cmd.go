package cmd

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/dougsko/wormhole-william/version"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:     "wormhole-william",
	Short:   "Create a wormhole and transfer files through it.",
	Version: version.AgentVersion,
	Long: `Create a (magic) Wormhole and communicate through it.

  Wormholes are created by speaking the same magic CODE in two different
  places at the same time. Wormholes are secure against anyone who doesn't
  use the same code.`,
}

var (
	relayURL        string
	transitHelper   string
	appID           string
	noListen        bool
	verify          bool
	hideProgressBar bool

	versionTemplate = `{{with .Name}}{{printf "%s " .}}{{end}}{{printf "%s" .Version}}
`
)

// transitHelperAddress normalizes the --transit-helper value. The Python
// client uses Twisted endpoint syntax (tcp:HOST:PORT); we accept plain
// HOST:PORT as well. An empty value means "use the default transit relay".
func transitHelperAddress(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", nil
	}
	v = strings.TrimPrefix(v, "tcp:")
	host, port, err := net.SplitHostPort(v)
	if err != nil {
		return "", fmt.Errorf("unrecognized --transit-helper %q (want tcp:HOST:PORT)", v)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return "", fmt.Errorf("bad port in --transit-helper %q", v)
	}
	return net.JoinHostPort(host, port), nil
}

// envBool parses common spellings of true/false. Unrecognized values fall
// back to def.
func envBool(name string, def bool) bool {
	v, ok := os.LookupEnv(name)
	if !ok {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "t", "true", "y", "yes", "on":
		return true
	case "0", "f", "false", "n", "no", "off":
		return false
	}
	return def
}

func Execute() error {
	rootCmd.SetVersionTemplate(versionTemplate)

	rootCmd.PersistentFlags().StringVar(&relayURL, "relay-url", "", "rendezvous relay to use")
	if relayURL == "" {
		relayURL = os.Getenv("WORMHOLE_RELAY_URL")
	}

	rootCmd.PersistentFlags().StringVar(&transitHelper, "transit-helper", "", "transit relay to use (tcp:HOST:PORT)")
	if transitHelper == "" {
		transitHelper = os.Getenv("WORMHOLE_TRANSIT_HELPER")
	}

	rootCmd.PersistentFlags().StringVar(&appID, "appid", "", "appid to use")

	rootCmd.PersistentFlags().BoolVar(&noListen, "no-listen", false, "do not listen for direct transit connections (force relay)")

	rootCmd.AddCommand(recvCommand())
	rootCmd.AddCommand(sendCommand())
	rootCmd.AddCommand(completionCommand())
	return rootCmd.Execute()
}
