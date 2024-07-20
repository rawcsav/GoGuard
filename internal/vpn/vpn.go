package vpn

import (
	"GoGuard/internal/config"
	"GoGuard/internal/detect"
	"GoGuard/internal/network"
	"encoding/json"
	"fmt"
	"github.com/biter777/countries"
	"go.uber.org/zap"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const mullvadStatusAPI = "https://am.i.mullvad.net/json"

type VPNManager struct {
	Config *config.Config
	Logger *zap.Logger
}

func NewVPNManager(config *config.Config, logger *zap.Logger) *VPNManager {
	return &VPNManager{
		Config: config,
		Logger: logger,
	}
}
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
func (vm *VPNManager) MonitorConnection(originalDNS string) {
	defer func() {
		if err := network.RevertDefaultRoute(); err != nil {
			vm.Logger.Error("Failed to revert default route", zap.Error(err))
		}

		if err := network.RevertDNSConfig(originalDNS); err != nil {
			vm.Logger.Error("Failed to revert DNS config", zap.Error(err))
		}
	}()

	for {
		secure, _, _, _, _, _, _, err := VPNStatus()
		if err != nil || !secure {
			vm.Logger.Info("Connection is not secure or error occurred, switching servers...")

			selectedServer, err := detect.SelectBestServer(vm.Config.ServerName, vm.Config.CountryCode, vm.Config.UseLatencyBasedSelection)
			if err != nil {
				vm.Logger.Error("Failed to select server", zap.Error(err))
				continue
			}

			if err := vm.SwitchServer(selectedServer); err != nil {
				vm.Logger.Error("Failed to switch servers", zap.Error(err))
				if disconnectErr := DisconnectVPN(vm.Config.InterfaceName); disconnectErr != nil {
					vm.Logger.Error("Failed to disconnect VPN after switch failure", zap.Error(disconnectErr))
				}
				break
			}
		}
		time.Sleep(5 * time.Minute)
	}
}

func (vm *VPNManager) SwitchServer(server *detect.MullvadServer) error {
	err := DisconnectVPN(vm.Config.InterfaceName)
	if err != nil {
		return fmt.Errorf("failed to disconnect VPN: %v", err)
	}

	err = SetupVPN(vm.Config, server)
	if err != nil {
		if disconnectErr := DisconnectVPN(vm.Config.InterfaceName); disconnectErr != nil {
			vm.Logger.Error("Failed to disconnect VPN after setup failure", zap.Error(disconnectErr))
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
