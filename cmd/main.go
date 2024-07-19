package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"GoGuard/internal/config"
	"GoGuard/internal/detect"
	"GoGuard/internal/network"
	"GoGuard/internal/vpn"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

// newLogger provides a new zap.Logger instance.
func newLogger() (*zap.Logger, error) {
	return zap.NewProduction()
}

// loadConfig loads the configuration from the specified file.
func loadConfig(configFile string) (*config.Config, error) {
	return config.LoadConfig(configFile)
}

// ConfigFlags holds the command-line flags.
type ConfigFlags struct {
	ConfigFile   string
	Server       string
	Country      string
	DNS          string
	LatencyBased bool
}

// provideConfigFlags parses and provides the command-line flags.
func provideConfigFlags() ConfigFlags {
	configFile := flag.String("config", "config.yaml", "Path to configuration file")
	server := flag.String("server", "", "WireGuard server to connect to (e.g., se-mma-wg-001)")
	country := flag.String("country", "", "Country code for server selection")
	dns := flag.String("dns", "", "DNS server to use (comma-separated)")
	latencyBased := flag.Bool("latency", true, "Use latency-based server selection")
	flag.Parse()

	return ConfigFlags{
		ConfigFile:   *configFile,
		Server:       *server,
		Country:      *country,
		DNS:          *dns,
		LatencyBased: *latencyBased,
	}
}

// selectBestServer selects the best server based on the configuration.
func selectBestServer(cfg *config.Config) (*detect.MullvadServer, error) {
	return detect.SelectBestServer(cfg.ServerName, cfg.CountryCode, cfg.UseLatencyBasedSelection)
}

func run(lc fx.Lifecycle, logger *zap.Logger, cfg *config.Config, selectedServer *detect.MullvadServer, flags ConfigFlags) {
	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			if flags.Server != "" {
				cfg.ServerName = flags.Server
			}
			if flags.Country != "" {
				cfg.CountryCode = flags.Country
			}
			if flags.DNS != "" {
				cfg.DNS = strings.Split(flags.DNS, ",")
			}
			cfg.UseLatencyBasedSelection = flags.LatencyBased

			fmt.Printf("Selected server: %s (%s, %s)\n", selectedServer.Hostname, selectedServer.CountryName, selectedServer.IPv4AddrIn)
			cfg.ServerName = selectedServer.Hostname
			fmt.Printf("Configuration:\n%+v\n", cfg)

			originalDNS, err := network.SaveOriginalDNSConfig()
			if err != nil {
				cleanup(cfg.InterfaceName, originalDNS)
				return fmt.Errorf("failed to save original DNS config: %v", err)
			}

			err = vpn.SetupVPN(cfg, selectedServer)
			if err != nil {
				cleanup(cfg.InterfaceName, originalDNS)
				return fmt.Errorf("failed to setup VPN: %v", err)
			}

			err = network.SetupRoutingAndDNS(cfg.InterfaceName, cfg.DNS)
			if err != nil {
				cleanup(cfg.InterfaceName, originalDNS)
				return fmt.Errorf("failed to setup routing and DNS: %v", err)
			}

			go vpn.MonitorConnection(cfg, originalDNS)

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

			go func() {
				<-sigChan
				logger.Info("Received termination signal. Cleaning up...")
				cleanup(cfg.InterfaceName, originalDNS)
				logger.Info("Cleanup complete. Exiting.")
				os.Exit(0)
			}()

			return nil
		},
	})
}

// cleanup reverts the DNS configuration and disconnects the VPN.
func cleanup(interfaceName, originalDNS string) {
	if err := vpn.DisconnectVPN(interfaceName); err != nil {
		log.Printf("Failed to disconnect VPN: %v", err)
	}
	if err := network.RevertDefaultRoute(); err != nil {
		log.Printf("Failed to revert default route: %v", err)
	}
	if err := network.RevertDNSConfig(originalDNS); err != nil {
		log.Printf("Failed to revert DNS config: %v", err)
	}
}

func main() {
	app := fx.New(
		fx.Provide(
			newLogger,
			provideConfigFlags,
			func(flags ConfigFlags) string { return flags.ConfigFile },
			loadConfig,
			selectBestServer,
		),
		fx.Invoke(run),
	)

	app.Run()
}
