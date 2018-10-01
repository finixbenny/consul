package create

import (
	"flag"
	"fmt"
	"io/ioutil"
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

	kind := ""
	if c.server {
		kind = "server"
	} else if c.client {
		kind = "client"
	} else if c.cli {
		kind = "cli"
	} else {
		c.UI.Error("Neither client or server - should not happen")
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

	name := fmt.Sprintf("%s.node.%s.consul", kind, c.dc)
	pub, priv, err := connect.GenerateCert(signer, string(cert), sn, name)
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	fileName := fmt.Sprintf("consul-%s-key.pem", kind)
	pkFile, err := os.Create(fileName)
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	pkFile.WriteString(priv)
	c.UI.Output("==> saved " + fileName)
	fileName = fmt.Sprintf("consul-%s.pem", kind)
	certFile, err := os.Create(fileName)
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	certFile.WriteString(pub)
	c.UI.Output("==> saved " + fileName)
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
