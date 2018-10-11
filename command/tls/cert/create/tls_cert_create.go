package create

import (
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"

	"github.com/hashicorp/consul/agent/connect"
	"github.com/hashicorp/consul/command/flags"
	"github.com/mitchellh/cli"
)

func New(ui cli.Ui) *cmd {
	c := &cmd{UI: ui}
	c.init()
	return c
}

type cmd struct {
	UI     cli.Ui
	flags  *flag.FlagSet
	ca     string
	key    string
	server bool
	client bool
	cli    bool
	dc     string
	domain string
	help   string
}

func (c *cmd) init() {
	c.flags = flag.NewFlagSet("", flag.ContinueOnError)
	c.flags.StringVar(&c.ca, "ca-file", "consul-ca.pem", "Provide the ca")
	c.flags.StringVar(&c.key, "key-file", "consul-ca-key.pem", "Provide the key")
	c.flags.BoolVar(&c.server, "server", false, "Generate server certificate")
	c.flags.BoolVar(&c.client, "client", false, "Generate client certificate")
	c.flags.BoolVar(&c.cli, "cli", false, "Generate cli certificate")
	c.flags.StringVar(&c.dc, "dc", "global", "Provide the datacenter")
	c.flags.StringVar(&c.domain, "domain", "consul", "Provide the domain")
	c.help = flags.Usage(help, c.flags)
}

func (c *cmd) Run(args []string) int {
	if err := c.flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		c.UI.Error(fmt.Sprintf("Failed to parse args: %v", err))
		return 1
	}
	if c.ca == "" {
		c.UI.Error("Please provide the ca")
		return 1
	}
	if c.key == "" {
		c.UI.Error("Please provide the key")
		return 1
	}

	if !((c.server && !c.client && !c.cli) ||
		(!c.server && c.client && !c.cli) ||
		(!c.server && !c.client && c.cli)) {
		c.UI.Error("Please provide either -server, -client, or -cli")
		return 1
	}

	prefix := "consul"
	if len(c.flags.Args()) > 0 {
		prefix = c.flags.Args()[0]
	}

	var DNSNames []string
	var IPAddresses []net.IP
	var extKeyUsage []x509.ExtKeyUsage
	var pkFileName, certFileName string

	if c.server {
		DNSNames = []string{fmt.Sprintf("server.%s.%s", c.dc, c.domain), "localhost"}
		IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		certFileName = fmt.Sprintf("%s-server.pem", prefix)
		pkFileName = fmt.Sprintf("%s-server-key.pem", prefix)
	} else if c.client {
		DNSNames = []string{"localhost"}
		IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		certFileName = fmt.Sprintf("%s-client.pem", prefix)
		pkFileName = fmt.Sprintf("%s-client-key.pem", prefix)
	} else if c.cli {
		DNSNames = []string{}
		IPAddresses = []net.IP{}
		certFileName = fmt.Sprintf("%s-cli.pem", prefix)
		pkFileName = fmt.Sprintf("%s-cli-key.pem", prefix)
	} else {
		c.UI.Error("Neither client, cli nor server - should not happen")
		return 1
	}

	cert, err := ioutil.ReadFile(c.ca)
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	key, err := ioutil.ReadFile(c.key)
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	signer, err := connect.ParseSigner(string(key))
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	sn, err := connect.GenerateSerialNumber()
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	pub, priv, err := connect.GenerateCert(signer, string(cert), sn, DNSNames, IPAddresses, extKeyUsage)
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	certFile, err := os.Create(certFileName)
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	certFile.WriteString(pub)
	c.UI.Output("==> saved " + certFileName)

	pkFile, err := os.Create(pkFileName)
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	pkFile.WriteString(priv)
	c.UI.Output("==> saved " + pkFileName)

	return 0
}

func (c *cmd) Synopsis() string {
	return synopsis
}

func (c *cmd) Help() string {
	return c.help
}

const synopsis = "Create a new certificate"
const help = `
Usage: consul tls cert

	Create a new certificate

	$ consul tls cert -ca-file consul-ca.pem -ca-key-file consul-ca-key.pem
`
