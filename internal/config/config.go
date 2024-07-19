package config

import (
	"GoGuard/internal/detect"
	"fmt"
	"github.com/spf13/viper"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
)

type Config struct {
	MullvadAccountNumber     string   `mapstructure:"mullvad_account_number"`
	InterfaceName            string   `mapstructure:"interface_name"`
	ServerName               string   `mapstructure:"server_name"`
	CountryCode              string   `mapstructure:"country_code"`
	LocalNetworkCIDR         string   `mapstructure:"local_network_cidr"`
	UseLatencyBasedSelection bool     `mapstructure:"use_latency_based_selection"`
	DNS                      []string `mapstructure:"dns"`
	PreUp                    []string `mapstructure:"pre_up"`
	PostUp                   []string `mapstructure:"post_up"`
	PreDown                  []string `mapstructure:"pre_down"`
	PostDown                 []string `mapstructure:"post_down"`
}

type MullvadServer struct {
	PublicKey   string
	IPv4AddrIn  string
	CountryCode string
	IPv4Address string
}

func LoadConfig(configFile string) (*Config, error) {
	v := viper.New()

	// Set default values
	v.SetDefault("interface_name", "wg0")
	v.SetDefault("dns", []string{"10.64.0.1"})
	v.AutomaticEnv()
	v.SetEnvPrefix("GOGUARD")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Read from config file if specified
	if configFile != "" {
		v.SetConfigFile(configFile)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("unable to decode into struct: %w", err)
	}

	// Validate required fields
	if config.MullvadAccountNumber == "" {
		return nil, fmt.Errorf("Mullvad account number is required")
	}

	return &config, nil
}

func getOrGenerateKeys(interfaceName string) (privateKey, publicKey string, err error) {
	configPath := GetWireGuardConfigPath(interfaceName)
	if _, err := os.Stat(configPath); err == nil {
		// Configuration file exists, extract keys
		existingConfig, err := ioutil.ReadFile(configPath)
		if err != nil {
			return "", "", fmt.Errorf("failed to read existing WireGuard config: %v", err)
		}

		privateKey = extractKey(string(existingConfig), "PrivateKey")
		if privateKey == "" {
			privateKey, err = generatePrivateKey()
			if err != nil {
				return "", "", fmt.Errorf("failed to generate private key: %v", err)
			}
		}
	} else {
		// Configuration file does not exist, generate new private key
		privateKey, err = generatePrivateKey()
		if err != nil {
			return "", "", fmt.Errorf("failed to generate private key: %v", err)
		}
	}

	// Always generate the public key from the private key
	publicKey, err = generatePublicKey(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate public key: %v", err)
	}

	return privateKey, publicKey, nil
}

func validateKeys(privateKey, publicKey string) error {
	if len(privateKey) != 44 || len(publicKey) != 44 {
		return fmt.Errorf("invalid key length")
	}
	// Add more validation if necessary
	return nil
}

func GenerateWireGuardConfig(cfg *Config, server *detect.MullvadServer) (string, error) {
	privateKey, publicKey, err := getOrGenerateKeys(cfg.InterfaceName)
	if err != nil {
		return "", err
	}

	clientIP, err := getClientIP(cfg.MullvadAccountNumber, publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to get client IP: %v", err)
	}

	config := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32
DNS = %s

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = %s:51820
`, privateKey, clientIP, strings.Join(cfg.DNS, ", "), server.PublicKey, server.IPv4AddrIn)

	return ModifyWireGuardConfig(cfg, config), nil
}

func extractKey(configContent, keyName string) string {
	for _, line := range strings.Split(configContent, "\n") {
		if strings.HasPrefix(line, keyName) {
			parts := strings.SplitN(line, "=", 2) // Split into exactly 2 parts
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[1])
				return key
			}
		}
	}
	return ""
}

func generatePrivateKey() (string, error) {
	cmd := exec.Command("wg", "genkey")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func generatePublicKey(privateKey string) (string, error) {
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(privateKey)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to generate public key: %v", err)
	}
	return strings.TrimSpace(string(output)), nil
}

func getClientIP(accountNumber, publicKey string) (string, error) {
	apiURL := "https://api.mullvad.net/wg/"
	data := url.Values{}
	data.Set("account", accountNumber)
	data.Set("pubkey", publicKey)

	resp, err := http.PostForm(apiURL, data)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("failed to fetch server info: status code %d, body: %s", resp.StatusCode, string(body))
	}

	clientIPs := strings.TrimSpace(string(body))
	ips := strings.Split(clientIPs, ",")
	if len(ips) < 1 {
		return "", fmt.Errorf("no IP addresses received from Mullvad API")
	}

	ipv4 := strings.Split(ips[0], "/")[0]
	return ipv4, nil
}
func ModifyWireGuardConfig(c *Config, configContent string) string {
	parts := strings.SplitN(configContent, "[Peer]", 2)
	if len(parts) != 2 {
		// If we can't split the config, just append the commands at the end
		return configContent + buildCommands(c)
	}

	interfacePart := strings.TrimRight(parts[0], "\n")
	peerPart := "[Peer]" + parts[1]

	commands := buildCommands(c)

	return interfacePart + "\n\n" + commands + "\n" + peerPart
}

func buildCommands(c *Config) string {
	var commands string
	for _, cmd := range c.PreUp {
		commands += fmt.Sprintf("PreUp = %s\n", cmd)
	}
	for _, cmd := range c.PostUp {
		commands += fmt.Sprintf("PostUp = %s\n", cmd)
	}
	for _, cmd := range c.PreDown {
		commands += fmt.Sprintf("PreDown = %s\n", cmd)
	}
	for _, cmd := range c.PostDown {
		commands += fmt.Sprintf("PostDown = %s\n", cmd)
	}
	return strings.TrimRight(commands, "\n")
}

func GetWireGuardConfigPath(interfaceName string) string {
	return fmt.Sprintf("/etc/wireguard/%s.conf", interfaceName)
}
