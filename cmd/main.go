package main

import (
	"GoGuard/pkg/detect"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

// Mullvad API endpoint for user status
const mullvadStatusAPI = "https://am.i.mullvad.net/json"

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

	// Safely assert types, checking for nil values
	secure, _ := result["mullvad_exit_ip"].(bool)
	ip, _ := result["ip"].(string)
	country, _ := result["country"].(string)
	city, _ := result["city"].(string)
	mullvadServer, _ := result["mullvad_server"].(bool)
	organization, _ := result["organization"].(string)
	blacklisted, _ := result["blacklisted"].(bool)

	return secure, ip, country, city, mullvadServer, organization, blacklisted, nil
}

// main function to run the application
func main() {
	secure, ip, country, city, mullvadServer, organization, blacklisted, err := VPNStatus()
	if err != nil {
		log.Fatalf("Error checking VPN status: %v", err)
	}

	fmt.Printf("Current IP: %s\n", ip)
	fmt.Printf("Country: %s\n", country)
	fmt.Printf("City: %s\n", city)
	fmt.Printf("Organization: %s\n", organization)
	if secure {
		fmt.Println("Your connection is secure.")
	} else {
		fmt.Println("Your connection is NOT secure.")
	}
	if mullvadServer {
		fmt.Println("You are connected to a Mullvad server.")
	} else {
		fmt.Println("You are NOT connected to a Mullvad server.")
	}
	if blacklisted {
		fmt.Println("Your IP is blacklisted.")
	} else {
		fmt.Println("Your IP is not blacklisted.")
	}

	bestServer, latency, err := detect.FindBestServer(country)
	if err != nil {
		log.Fatalf("Error finding best server: %v", err)
	}

	fmt.Printf("Best server: %s (%s) in %s with latency %v\n",
		bestServer.Hostname, bestServer.IPv4AddrIn, bestServer.CountryName, latency)
}
