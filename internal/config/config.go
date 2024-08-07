package config

import (
	"GoGuard/internal/detect"
	"GoGuard/internal/mullvad"
	"fmt"
	"github.com/spf13/viper"
	"io/ioutil"
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

func LoadConfig(configFile string) (*Config, error) {
	v := viper.New()
	setDefaults(v)
	v.AutomaticEnv()
	v.SetEnvPrefix("GOGUARD")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if configFile != "" {
		if err := readConfigFile(v, configFile); err != nil {
			return nil, err
		}
	}

	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("unable to decode into struct: %w", err)
	}

	if err := validateConfig(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("interface_name", "wg0")
	v.SetDefault("dns", []string{"10.64.0.1"})
}

func readConfigFile(v *viper.Viper, configFile string) error {
	v.SetConfigFile(configFile)
	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("error reading config file: %w", err)
	}
	return nil
}

func validateConfig(config *Config) error {
	if config.MullvadAccountNumber == "" {
		return fmt.Errorf("Mullvad account number is required")
	}
	return nil
}

func getOrGenerateKeys(interfaceName string) (privateKey, publicKey string, err error) {
	configPath := GetWireGuardConfigPath(interfaceName)
	if _, err := os.Stat(configPath); err == nil {
		privateKey, err = extractPrivateKey(configPath)
		if err != nil {
			return "", "", err
		}
	} else {
		privateKey, err = generatePrivateKey()
		if err != nil {
			return "", "", err
		}
	}

	publicKey, err = generatePublicKey(privateKey)
	if err != nil {
		return "", "", err
	}

	return privateKey, publicKey, nil
}

func extractPrivateKey(configPath string) (string, error) {
	existingConfig, err := ioutil.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("failed to read existing WireGuard config: %v", err)
	}
	privateKey := extractKey(string(existingConfig), "PrivateKey")
	if privateKey == "" {
		privateKey, err = generatePrivateKey()
		if err != nil {
			return "", fmt.Errorf("failed to generate private key: %v", err)
		}
	}
	return privateKey, nil
}

func GenerateWireGuardConfig(cfg *Config, server *detect.MullvadServer) (string, error) {
	privateKey, publicKey, err := getOrGenerateKeys(cfg.InterfaceName)
	if err != nil {
		return "", err
	}

	clientIP, err := mullvad.GetClientIP(cfg.MullvadAccountNumber, publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to get client IP: %v", err)
	}

	config := buildWireGuardConfig(cfg, server, privateKey, clientIP)
	return ModifyWireGuardConfig(cfg, config), nil
}

func buildWireGuardConfig(cfg *Config, server *detect.MullvadServer, privateKey, clientIP string) string {
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32
DNS = %s

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = %s:51820
`, privateKey, clientIP, strings.Join(cfg.DNS, ", "), server.PublicKey, server.IPv4AddrIn)
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
