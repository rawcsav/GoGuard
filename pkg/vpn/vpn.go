package vpn

import (
	"GoGuard/pkg/config"
	"GoGuard/pkg/detect"
	"GoGuard/pkg/network"
	"encoding/json"
	"fmt"
	"github.com/biter777/countries"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const mullvadStatusAPI = "https://am.i.mullvad.net/json"

func SetupVPN(cfg *config.Config, server *detect.MullvadServer) error {
	wireGuardConfig, err := config.GenerateWireGuardConfig(cfg, server)
	if err != nil {
		return fmt.Errorf("failed to generate WireGuard config: %v", err)
	}

	configPath := config.GetWireGuardConfigPath(cfg.InterfaceName)

	// Ensure the directory exists
	configDir := filepath.Dir(configPath)
	err = os.MkdirAll(configDir, 0700)
	if err != nil {
		return fmt.Errorf("failed to create directory %s: %v", configDir, err)
	}

	err = os.WriteFile(configPath, []byte(wireGuardConfig), 0600)
	if err != nil {
		return fmt.Errorf("failed to write WireGuard config: %v", err)
	}

	cmd := exec.Command("sudo", "wg-quick", "up", cfg.InterfaceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to bring up WireGuard interface: %v\nOutput: %s", err, string(output))
	}

	return nil
}

func MonitorConnection(cfg *config.Config, originalDNS string) {
	defer func() {
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

			// Re-select the best server
			selectedServer, err := detect.SelectBestServer(cfg.ServerName, cfg.CountryCode, cfg.UseLatencyBasedSelection)
			if err != nil {
				log.Printf("Failed to select server: %v", err)
				continue
			}

			if err := SwitchServer(cfg, selectedServer); err != nil {
				log.Printf("Failed to switch servers: %v", err)
				// If switching server fails, stop the connection
				if disconnectErr := DisconnectVPN(cfg.InterfaceName); disconnectErr != nil {
					log.Printf("Failed to disconnect VPN after switch failure: %v", disconnectErr)
				}
				break
			}
		}
		time.Sleep(5 * time.Minute)
	}
}

func SwitchServer(cfg *config.Config, server *detect.MullvadServer) error {
	err := DisconnectVPN(cfg.InterfaceName)
	if err != nil {
		return fmt.Errorf("failed to disconnect VPN: %v", err)
	}

	err = SetupVPN(cfg, server)
	if err != nil {
		// If setting up the VPN fails, stop the connection
		if disconnectErr := DisconnectVPN(cfg.InterfaceName); disconnectErr != nil {
			log.Printf("Failed to disconnect VPN after setup failure: %v", disconnectErr)
		}
		return fmt.Errorf("failed to setup VPN: %v", err)
	}

	return nil
}

func DisconnectVPN(interfaceName string) error {
	cmd := exec.Command("sudo", "wg-quick", "down", interfaceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to disconnect VPN: %v\nOutput: %s", err, string(output))
	}
	return nil
}

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

func validateCountry(country string) string {
	// If it's already a 2-letter country code, validate and return it
	if len(country) == 2 {
		if countries.ByName(country).IsValid() {
			return strings.ToUpper(country)
		}
	}

	// If it's a country name, try to get its code
	countryCode := countries.ByName(country)
	if countryCode.IsValid() {
		return countryCode.Alpha2()
	}

	// If we couldn't validate the country, return an empty string
	return ""
}
