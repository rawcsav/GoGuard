package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"GoGuard/pkg/config"
	"GoGuard/pkg/detect"
	"GoGuard/pkg/network"
	"GoGuard/pkg/vpn"
)

func main() {
	configFile := flag.String("config", "config.yaml", "Path to configuration file")
	server := flag.String("server", "", "WireGuard server to connect to (e.g., se-mma-wg-001)")
	country := flag.String("country", "", "Country code for server selection")
	dns := flag.String("dns", "", "DNS server to use (comma-separated)")
	latencyBased := flag.Bool("latency", false, "Use latency-based server selection")

	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if *server != "" {
		cfg.ServerName = *server
	}
	if *country != "" {
		cfg.CountryCode = *country
	}

	if *dns != "" {
		cfg.DNS = strings.Split(*dns, ",")
	}
	if *latencyBased {
		cfg.UseLatencyBasedSelection = true
	}

	// Select the best server based on the configuration
	selectedServer, err := detect.SelectBestServer(cfg.ServerName, cfg.CountryCode, cfg.UseLatencyBasedSelection)
	if err != nil {
		log.Fatalf("Failed to select server: %v", err)
	}

	fmt.Printf("Selected server: %s (%s, %s)\n", selectedServer.Hostname, selectedServer.CountryName, selectedServer.IPv4AddrIn)

	// Update cfg with the selected server information
	cfg.ServerName = selectedServer.Hostname

	fmt.Printf("Configuration:\n%+v\n", cfg)

	// Save original DNS config
	originalDNS, err := network.SaveOriginalDNSConfig()
	if err != nil {
		cleanup(cfg.InterfaceName, originalDNS)
		log.Fatalf("Failed to save original DNS config: %v", err)
	}

	// Setup VPN
	err = vpn.SetupVPN(cfg, selectedServer)
	if err != nil {
		cleanup(cfg.InterfaceName, originalDNS)
		log.Fatalf("Failed to setup VPN: %v", err)
	}

	// Setup routing and DNS for the interface
	err = network.SetupRoutingAndDNS(cfg.InterfaceName, cfg.DNS)
	if err != nil {
		cleanup(cfg.InterfaceName, originalDNS)
		log.Fatalf("Failed to setup routing and DNS: %v", err)
	}

	// Start VPN connection monitoring
	go vpn.MonitorConnection(cfg, originalDNS)

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for termination signal
	<-sigChan

	// Cleanup and disconnect
	log.Println("Received termination signal. Cleaning up...")
	cleanup(cfg.InterfaceName, originalDNS)
	log.Println("Cleanup complete. Exiting.")
}

// cleanup reverts the DNS configuration and disconnects the VPN
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
