// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"fmt"
	"os"

	openaisecrets "github.com/gitrgoliveira/vault-plugin-secrets-openai/plugin"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
)

// Build information injected at link time via -ldflags "-X main.version=... etc".
// Defaults are used for local/dev builds where no ldflags are provided.
var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

func main() {
	// Support a -version/--version flag for inspecting the embedded build info.
	for _, arg := range os.Args[1:] {
		if arg == "-version" || arg == "--version" {
			fmt.Printf("vault-plugin-secrets-openai %s (commit %s, built %s)\n", version, commit, buildTime)
			os.Exit(0)
		}
	}

	apiClientMeta := &api.PluginAPIClientMeta{}

	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		logger := hclog.New(&hclog.LoggerOptions{})
		logger.Error("error parsing flags", "error", err)
		os.Exit(1)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: openaisecrets.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	})
	if err != nil {
		logger := hclog.New(&hclog.LoggerOptions{})
		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
