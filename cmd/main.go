package main

import (
	"GoGuard/pkg/detect"
	"encoding/json"
	"fmt"
	"github.com/biter777/countries"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
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

	// Validate if the country is already a country code
	countryCode := validateCountry(country)

	return secure, ip, countryCode, city, mullvadServer, organization, blacklisted, nil
}

// validateCountry checks if the input is a valid country code or converts the country name to a country code
func validateCountry(country string) string {
	// Regex to match two-letter country codes
	re := regexp.MustCompile(`^[A-Z]{2}$`)
	if re.MatchString(country) {
		return country
	}
	// Convert country name to country code
	return countries.ByName(country).Alpha2()
}

// main function to run the application
func main() {
	secure, ip, countryCode, city, mullvadServer, organization, blacklisted, err := VPNStatus()
	if err != nil {
		log.Fatalf("Error checking VPN status: %v", err)
	}

	fmt.Printf("Current IP: %s\n", ip)
	fmt.Printf("Country Code: %s\n", countryCode)
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

	bestServer, latency, err := detect.FindBestServer(countryCode)
	if err != nil {
		log.Fatalf("Error finding best server: %v", err)
	}

	fmt.Printf("Best server: %s (%s) in %s with latency %v\n",
		bestServer.Hostname, bestServer.IPv4AddrIn, bestServer.CountryName, latency)
}
