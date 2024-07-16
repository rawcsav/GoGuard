package config

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	MullvadAccountNumber     string
	InterfaceName            string
	ServerName               string
	CountryCode              string
	EnableMultihop           bool
	EnableKillSwitch         bool
	LocalNetworkCIDR         string
	UseSOCKS5Proxy           bool
	UseLatencyBasedSelection bool
	SOCKS5ProxyPort          int
	DNS                      []string
	PreUp                    []string
	PostUp                   []string
	PreDown                  []string
	PostDown                 []string
}

func LoadConfig() (*Config, error) {
	config := &Config{}

	config.MullvadAccountNumber = os.Getenv("MULLVAD_ACCOUNT_NUMBER")
	config.InterfaceName = os.Getenv("INTERFACE_NAME")
	config.ServerName = os.Getenv("SERVER_NAME")
	config.CountryCode = os.Getenv("COUNTRY_CODE")
	config.EnableMultihop, _ = strconv.ParseBool(os.Getenv("ENABLE_MULTIHOP"))
	config.EnableKillSwitch, _ = strconv.ParseBool(os.Getenv("ENABLE_KILL_SWITCH"))
	config.LocalNetworkCIDR = os.Getenv("LOCAL_NETWORK_CIDR")
	config.UseSOCKS5Proxy, _ = strconv.ParseBool(os.Getenv("USE_SOCKS5_PROXY"))
	config.UseLatencyBasedSelection, _ = strconv.ParseBool(os.Getenv("USE_LATENCY_BASED_SELECTION"))
	config.SOCKS5ProxyPort, _ = strconv.Atoi(os.Getenv("SOCKS5_PROXY_PORT"))

	config.DNS = strings.Split(os.Getenv("DNS"), ",")
	config.PreUp = strings.Split(os.Getenv("PREUP"), ",")
	config.PostUp = strings.Split(os.Getenv("POSTUP"), ",")
	config.PreDown = strings.Split(os.Getenv("PREDOWN"), ",")
	config.PostDown = strings.Split(os.Getenv("POSTDOWN"), ",")

	if config.MullvadAccountNumber == "" || config.InterfaceName == "" {
		return nil, fmt.Errorf("missing required environment variables")
	}

	return config, nil
}

func LoadCustomConfig(filePath string) (*Config, error) {
	config := &Config{}

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read custom config file: %v", err)
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "MULLVAD_ACCOUNT_NUMBER":
			config.MullvadAccountNumber = value
		case "INTERFACE_NAME":
			config.InterfaceName = value
		case "SERVER_NAME":
			config.ServerName = value
		case "COUNTRY_CODE":
			config.CountryCode = value
		case "ENABLE_MULTIHOP":
			config.EnableMultihop, _ = strconv.ParseBool(value)
		case "ENABLE_KILL_SWITCH":
			config.EnableKillSwitch, _ = strconv.ParseBool(value)
		case "LOCAL_NETWORK_CIDR":
			config.LocalNetworkCIDR = value
		case "USE_SOCKS5_PROXY":
			config.UseSOCKS5Proxy, _ = strconv.ParseBool(value)
		case "USE_LATENCY_BASED_SELECTION":
			config.UseLatencyBasedSelection, _ = strconv.ParseBool(value)
		case "SOCKS5_PROXY_PORT":
			config.SOCKS5ProxyPort, _ = strconv.Atoi(value)
		case "DNS":
			config.DNS = strings.Split(value, ",")
		case "PREUP":
			config.PreUp = strings.Split(value, ",")
		case "POSTUP":
			config.PostUp = strings.Split(value, ",")
		case "PREDOWN":
			config.PreDown = strings.Split(value, ",")
		case "POSTDOWN":
			config.PostDown = strings.Split(value, ",")
		}
	}

	if config.MullvadAccountNumber == "" || config.InterfaceName == "" {
		return nil, fmt.Errorf("missing required configuration in custom config")
	}

	return config, nil
}

func GetConfigTemplate(config *Config) (string, error) {
	url := fmt.Sprintf("https://api.mullvad.net/v1/account/%s/wireguard-config/", config.MullvadAccountNumber)
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to fetch WireGuard config: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	log.Printf("Config file created for interface %s", config.InterfaceName)

	return string(body), nil
}

func WriteConfig(filePath, config string) error {
	return ioutil.WriteFile(filePath, []byte(config), 0600)
}

func (c *Config) ModifyWireguardConfig(configContent string) string {
	// Add kill switch
	if c.EnableKillSwitch {
		configContent += fmt.Sprintf("\nPostUp = iptables -I OUTPUT ! -o %s -m mark ! --mark $(wg show %s fwmark) -m addrtype ! --dst-type LOCAL -j REJECT\n", c.InterfaceName, c.InterfaceName)
		configContent += fmt.Sprintf("PreDown = iptables -D OUTPUT ! -o %s -m mark ! --mark $(wg show %s fwmark) -m addrtype ! --dst-type LOCAL -j REJECT\n", c.InterfaceName, c.InterfaceName)
	}

	// Add local network sharing
	if c.LocalNetworkCIDR != "" {
		configContent += fmt.Sprintf("\nPostUp = iptables -I OUTPUT ! -o %s -d %s -j ACCEPT\n", c.InterfaceName, c.LocalNetworkCIDR)
		configContent += fmt.Sprintf("PreDown = iptables -D OUTPUT ! -o %s -d %s -j ACCEPT\n", c.InterfaceName, c.LocalNetworkCIDR)
	}

	// Add SOCKS5 proxy
	if c.UseSOCKS5Proxy {
		configContent += fmt.Sprintf("\nPostUp = iptables -t nat -A PREROUTING -p tcp --dport %d -j REDIRECT --to-ports 1080\n", c.SOCKS5ProxyPort)
		configContent += fmt.Sprintf("PreDown = iptables -t nat -D PREROUTING -p tcp --dport %d -j REDIRECT --to-ports 1080\n", c.SOCKS5ProxyPort)
	}

	// Add custom DNS
	if len(c.DNS) > 0 {
		configContent += "\nDNS = " + strings.Join(c.DNS, "\nDNS = ") + "\n"
	}

	// Add pre and post commands
	for _, cmd := range c.PreUp {
		configContent += fmt.Sprintf("\nPreUp = %s\n", cmd)
	}
	for _, cmd := range c.PostUp {
		configContent += fmt.Sprintf("\nPostUp = %s\n", cmd)
	}
	for _, cmd := range c.PreDown {
		configContent += fmt.Sprintf("\nPreDown = %s\n", cmd)
	}
	for _, cmd := range c.PostDown {
		configContent += fmt.Sprintf("\nPostDown = %s\n", cmd)
	}

	return configContent
}
