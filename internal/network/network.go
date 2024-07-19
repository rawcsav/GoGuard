package network

import (
	"fmt"
	"io/ioutil"
	"os/exec"
	"runtime"
	"strings"
)

// SetupRoutingAndDNS sets up the default route and DNS configuration based on the OS.
func SetupRoutingAndDNS(interfaceName string, dnsServers []string) error {
	// Only set the default route on Linux systems
	if runtime.GOOS == "linux" {
		err := SetDefaultRoute(interfaceName)
		if err != nil {
			return fmt.Errorf("failed to set default route: %v", err)
		}
	}

	if runtime.GOOS == "linux" {

		err := SetDNSConfig(dnsServers)
		if err != nil {
			return fmt.Errorf("failed to set DNS config: %v", err)
		}
	}
	return nil
}

// SetDefaultRoute sets the default route to use the VPN interface
func SetDefaultRoute(interfaceName string) error {
	cmd := exec.Command("sudo", "route", "add", "default", interfaceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set default route: %v\nOutput: %s", err, string(output))
	}
	return nil
}

// RevertDefaultRoute reverts the default route back to the original interface
func RevertDefaultRoute() error {
	if runtime.GOOS == "linux" {
		cmd := exec.Command("sudo", "route", "delete", "default")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to delete default route: %v\nOutput: %s", err, string(output))
		}
	}
	return nil
}

// SetDNSConfig sets the DNS servers for the system
func SetDNSConfig(dnsServers []string) error {
	resolvConf := "nameserver " + strings.Join(dnsServers, "\nnameserver ") + "\n"
	err := ioutil.WriteFile("/etc/resolv.conf", []byte(resolvConf), 0644)
	if err != nil {
		return fmt.Errorf("failed to write DNS config: %v", err)
	}
	return nil
}

// RevertDNSConfig reverts the DNS servers back to the original configuration
func RevertDNSConfig(originalConfig string) error {
	if runtime.GOOS == "linux" {
		err := ioutil.WriteFile("/etc/resolv.conf", []byte(originalConfig), 0644)
		if err != nil {
			return fmt.Errorf("failed to revert DNS config: %v", err)
		}
	}
	return nil
}

// SaveOriginalDNSConfig saves the current DNS configuration
func SaveOriginalDNSConfig() (string, error) {
	originalConfig, err := ioutil.ReadFile("/etc/resolv.conf")
	if err != nil {
		return "", fmt.Errorf("failed to read original DNS config: %v", err)
	}
	return string(originalConfig), nil
}