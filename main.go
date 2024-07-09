package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

// Mullvad API endpoint
const mullvadAPIURL = "https://am.i.mullvad.net/json"

// VPNStatus checks the current VPN status using Mullvad's API
func VPNStatus() (bool, string, string, string, bool, error) {
	resp, err := http.Get(mullvadAPIURL)
	if err != nil {
		return false, "", "", "", false, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, "", "", "", false, err
	}

	var result map[string]interface{}
	json.Unmarshal(body, &result)

	// Safely assert types, checking for nil values
	secure, ok := result["mullvad_exit_ip"].(bool)
	if !ok {
		return false, "", "", "", false, fmt.Errorf("unexpected type or nil for 'mullvad_exit_ip'")
	}

	ip, ok := result["ip"].(string)
	if !ok {
		return false, "", "", "", false, fmt.Errorf("unexpected type or nil for 'ip'")
	}

	country, ok := result["country"].(string)
	if !ok {
		country = "Unknown"
	}

	city, ok := result["city"].(string)
	if !ok {
		city = "Unknown"
	}

	mullvadServer, ok := result["mullvad_server"].(bool)
	if !ok {
		mullvadServer = false // Assuming false if not explicitly true
	}

	return secure, ip, country, city, mullvadServer, nil
}

// main function to run the application
func main() {
	secure, ip, country, city, mullvadServer, err := VPNStatus()
	if err != nil {
		log.Fatalf("Error checking VPN status: %v", err)
	}

	fmt.Printf("Current IP: %s\n", ip)
	fmt.Printf("Country: %s\n", country)
	fmt.Printf("City: %s\n", city)
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
}
