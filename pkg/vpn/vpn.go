package vpn

import (
	"GoGuard/pkg/config"
	"GoGuard/pkg/detect"
	"GoGuard/pkg/network"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/biter777/countries"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Mullvad API endpoint for user status
const mullvadStatusAPI = "https://am.i.mullvad.net/json"

func getWireguardConfigPath(interfaceName string) string {
	return filepath.Join("/etc/wireguard", fmt.Sprintf("%s.conf", interfaceName))
}

// VPNStatus checks the current VPN status using Mullvad's API
func VPNStatus() (bool, string, string, string, bool, string, bool, error) {
	resp, err := http.Get(mullvadStatusAPI)
	if err != nil {
		return false, "", "", "", false, "", false, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, "", "", "", false, "", false, err
	}

	var result map[string]interface{}
	json.Unmarshal(body, &result)

	secure, _ := result["mullvad_exit_ip"].(bool)
	ip, _ := result["ip"].(string)
	country, _ := result["country"].(string)
	city, _ := result["city"].(string)
	mullvadServer, _ := result["mullvad_server"].(bool)
	organization, _ := result["organization"].(string)
	blacklisted, _ := result["blacklisted"].(bool)

	countryCode := validateCountry(country)

	return secure, ip, countryCode, city, mullvadServer, organization, blacklisted, nil
}

// validateCountry checks if the input is a valid country code or converts the country name to a country code
func validateCountry(country string) string {
	re := regexp.MustCompile("^[A-Z]{2}$")
	if re.MatchString(country) {
		return country
	}
	return countries.ByName(country).Alpha2()
}

// switchServer switches to the best available Mullvad WireGuard servers based on user preferences
func switchServer(configTemplate string, cfg *config.Config) error {
	var bestServers []detect.MullvadServer
	var err error

	if cfg.ServerName != "" {
		// User specified a server, use it
		bestServers = []detect.MullvadServer{{Hostname: cfg.ServerName}}
	} else if cfg.CountryCode != "" {
		bestServers, err = detect.FindBestServersInCountry(cfg.CountryCode, 1)
		if cfg.EnableMultihop {
			var secondHop []detect.MullvadServer
			secondHop, err = detect.FindBestServersInCountry(cfg.CountryCode, 1)
			bestServers = append(bestServers, secondHop...)
		}
	} else {
		// Use latency-based selection
		bestServers, err = detect.FindBestServers(1)
		if cfg.EnableMultihop {
			var secondHop []detect.MullvadServer
			secondHop, err = detect.FindBestServers(1)
			bestServers = append(bestServers, secondHop...)
		}
	}

	if err != nil {
		return fmt.Errorf("error finding best servers: %v", err)
	}

	peerConfig := ""
	for _, server := range bestServers {
		peerConfig += fmt.Sprintf("[Peer]\nPublicKey = %s\nEndpoint = %s:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n\n",
			server.PublicKey, server.IPv4AddrIn)
	}

	newConfig := strings.Replace(configTemplate, "[PEER_CONFIG]", peerConfig, 1)

	// Apply custom configuration options
	newConfig = cfg.ModifyWireguardConfig(newConfig)

	log.Printf("Generated WireGuard config: %s", newConfig)

	configPath := getWireguardConfigPath(cfg.InterfaceName)
	err = ioutil.WriteFile(configPath, []byte(newConfig), 0600)
	if err != nil {
		return fmt.Errorf("failed to write WireGuard config: %v", err)
	}

	// Check if WireGuard interface is up before bringing it down
	cmd := exec.Command("sudo", "wg", "show", "wg0")
	if err := cmd.Run(); err == nil {
		err = exec.Command("sudo", "wg-quick", "down", "wg0").Run()
		if err != nil {
			return fmt.Errorf("failed to bring down WireGuard interface: %v", err)
		}
	}

	err = exec.Command("sudo", "wg-quick", "up", "wg0").Run()
	if err != nil {
		return fmt.Errorf("failed to bring up WireGuard interface: %v", err)
	}

	return nil
}

// MonitorConnection continuously monitors the VPN connection and switches servers if needed
func MonitorConnection(configTemplate string, cfg *config.Config, originalDNS string) {
	defer func() {
		// Revert network settings on exit
		if err := network.RevertDefaultRoute(); err != nil {
			log.Printf("Failed to revert default route: %v", err)
		}

		if err := network.RevertDNSConfig(originalDNS); err != nil {
			log.Printf("Failed to revert DNS config: %v", err)
		}
	}()

	for {
		secure, _, _, _, _, _, _, err := VPNStatus()
		if err != nil || !secure {
			log.Println("Connection is not secure or error occurred, switching servers...")
			if err := switchServer(configTemplate, cfg); err != nil {
				log.Printf("Failed to switch servers: %v", err)
			}
		}
		time.Sleep(5 * time.Minute) // Check every 5 minutes
	}
}

// ConfigureAutoStart sets up WireGuard to start automatically on boot
func ConfigureAutoStart(serverName string) error {
	cmd := exec.Command("sudo", "systemctl", "enable", fmt.Sprintf("wg-quick@%s", serverName))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to configure auto-start: %v\nOutput: %s", err, string(output))
	}
	return nil
}

// DisconnectVPN brings down the WireGuard interface
func DisconnectVPN() error {
	cmd := exec.Command("sudo", "wg-quick", "down", "wg0")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to disconnect VPN: %v\nOutput: %s", err, string(output))
	}
	return nil
}

// ConnectVPN brings up the WireGuard interface
func ConnectVPN() error {
	cmd := exec.Command("sudo", "wg-quick", "up", "wg0")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to connect VPN: %v\nOutput: %s", err, string(output))
	}
	return nil
}

// UpdateWireguardKeys rotates the WireGuard keys
func UpdateWireguardKeys(cfg *config.Config) error {
	// Generate new keys
	privateKey, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	pubCmd := exec.Command("wg", "pubkey")
	pubCmd.Stdin = strings.NewReader(string(privateKey))
	publicKey, err := pubCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to generate public key: %v", err)
	}

	configPath := getWireguardConfigPath(cfg.InterfaceName)
	configContent, err := ioutil.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read WireGuard config: %v", err)
	}

	newContent := regexp.MustCompile(`(?m)^PrivateKey = .*`).ReplaceAllString(
		string(configContent),
		fmt.Sprintf("PrivateKey = %s", strings.TrimSpace(string(privateKey))),
	)

	err = ioutil.WriteFile(configPath, []byte(newContent), 0600)
	if err != nil {
		return fmt.Errorf("failed to write updated WireGuard config: %v", err)
	}

	// Send the new public key to Mullvad's API
	if err := updateMullvadPublicKey(cfg.MullvadAccountNumber, strings.TrimSpace(string(publicKey))); err != nil {
		return fmt.Errorf("failed to update Mullvad public key: %v", err)
	}

	return nil
}

// updateMullvadPublicKey sends the new public key to Mullvad's API
func updateMullvadPublicKey(accountNumber, publicKey string) error {
	url := fmt.Sprintf("https://api.mullvad.net/v1/account/%s/wireguard-key/", accountNumber)
	data := map[string]string{
		"key": publicKey,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON data: %v", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("failed to update public key, status code: %d, response: %s", resp.StatusCode, string(body))
	}

	return nil
}
