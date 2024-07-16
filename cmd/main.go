package main

import (
	config2 "GoGuard/pkg/config"
	"GoGuard/pkg/network"
	"GoGuard/pkg/vpn"
	"flag"
	"github.com/joho/godotenv"
	"log"
	"path/filepath"
	"strings"
)

func main() {
	// Load environment variables from .env file
	err := godotenv.Load(filepath.Join("../", ".env"))
	if err != nil {
		log.Println("No .env file found")
	}

	multihop := flag.Bool("m", false, "Enable multihop (2 hops)")
	server := flag.String("s", "", "WireGuard server to connect to (e.g., se-mma-wg-001)")
	killSwitch := flag.Bool("k", false, "Enable kill switch")
	localNet := flag.String("l", "", "Local network CIDR for sharing (e.g., 192.168.1.0/24)")
	socks5 := flag.Bool("p", false, "Use SOCKS5 proxy for additional hop")
	autoStart := flag.Bool("a", false, "Configure to start automatically on boot")
	configFile := flag.String("c", "", "Path to custom configuration file")
	dns := flag.String("dns", "10.64.0.1", "DNS server to use (comma-separated)")
	preUp := flag.String("preup", "", "Pre-up commands (comma-separated)")
	postUp := flag.String("postup", "", "Post-up commands (comma-separated)")
	preDown := flag.String("predown", "", "Pre-down commands (comma-separated)")
	postDown := flag.String("postdown", "", "Post-down commands (comma-separated)")

	flag.Parse()

	var config *config2.Config
	if *configFile != "" {
		config, err = config2.LoadCustomConfig(*configFile)
	} else {
		config, err = config2.LoadConfig()
	}
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Ensure InterfaceName is set
	if config.InterfaceName == "" {
		log.Fatalf("InterfaceName must be specified")
	}

	// Apply customizations to config
	if *server != "" {
		config.ServerName = *server
	}
	config.EnableMultihop = *multihop
	config.EnableKillSwitch = *killSwitch
	config.LocalNetworkCIDR = *localNet
	config.UseSOCKS5Proxy = *socks5
	config.DNS = strings.Split(*dns, ",")
	config.PreUp = strings.Split(*preUp, ",")
	config.PostUp = strings.Split(*postUp, ",")
	config.PreDown = strings.Split(*preDown, ",")
	config.PostDown = strings.Split(*postDown, ",")

	// Get config template
	configTemplate, err := config2.GetConfigTemplate(config)
	if err != nil {
		log.Fatalf("Failed to load config template: %v", err)
	}

	// Save original DNS config
	originalDNS, err := network.SaveOriginalDNSConfig()
	if err != nil {
		log.Fatalf("Failed to save original DNS config: %v", err)
	}

	// Configure auto-start if requested
	if *autoStart {
		err := vpn.ConfigureAutoStart(config.ServerName)
		if err != nil {
			log.Printf("Failed to configure auto-start: %v", err)
		}
	}

	// Set default route and DNS
	err = network.SetDefaultRoute("wg0")
	if err != nil {
		log.Fatalf("Failed to set default route: %v", err)
	}

	err = network.SetDNSConfig(config.DNS)
	if err != nil {
		log.Fatalf("Failed to set DNS config: %v", err)
	}

	// Start VPN connection with multihop and/or SOCKS5 proxy if enabled
	go vpn.MonitorConnection(configTemplate, config, originalDNS)

	// Keep the main function running
	select {}
}
