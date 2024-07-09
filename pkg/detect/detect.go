package detect

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// MullvadServer represents a Mullvad VPN server.
type MullvadServer struct {
	Hostname    string `json:"hostname"`
	IPv4AddrIn  string `json:"ipv4_addr_in"`
	CountryName string `json:"country_name"`
}

func FetchMullvadServers(country string) ([]MullvadServer, error) {
	url := fmt.Sprintf("https://api.mullvad.net/www/relays/all/?filters={\"country_code\":\"%s\"}", country)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// Check if the response starts with '<', indicating HTML
	if strings.TrimSpace(string(body))[0] == '<' {
		return nil, fmt.Errorf("received HTML instead of JSON. Response body: %s", string(body[:100])) // Print first 100 characters
	}

	var servers []MullvadServer
	err = json.Unmarshal(body, &servers)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshaling failed: %v. Response body: %s", err, string(body[:100]))
	}

	if len(servers) == 0 {
		return nil, fmt.Errorf("no servers found for country: %s", country)
	}

	return servers, nil
}

// TCPPing performs a TCP ping to measure latency.
func TCPPing(ip string, port int) (time.Duration, error) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 2*time.Second)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	return time.Since(start), nil
}

// FindBestServer finds the Mullvad server with the lowest latency.
func FindBestServer(country string) (*MullvadServer, time.Duration, error) {
	servers, err := FetchMullvadServers(country)
	if err != nil {
		return nil, 0, err
	}

	type ServerLatency struct {
		Server  MullvadServer
		Latency time.Duration
	}

	results := make(chan ServerLatency)
	var wg sync.WaitGroup
	totalServers := len(servers)
	pingedServers := 0
	mu := &sync.Mutex{}

	for _, server := range servers {
		wg.Add(1)
		go func(server MullvadServer) {
			defer wg.Done()
			latency, err := TCPPing(server.IPv4AddrIn, 443) // Use HTTPS port
			mu.Lock()
			pingedServers++
			fmt.Printf("Pinged %d/%d servers\n", pingedServers, totalServers)
			mu.Unlock()
			if err != nil {
				fmt.Printf("Error pinging server %s (%s): %v\n", server.Hostname, server.IPv4AddrIn, err)
				return
			}
			results <- ServerLatency{Server: server, Latency: latency}
		}(server)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var serverLatencies []ServerLatency
	for result := range results {
		serverLatencies = append(serverLatencies, result)
	}

	sort.Slice(serverLatencies, func(i, j int) bool {
		return serverLatencies[i].Latency < serverLatencies[j].Latency
	})

	if len(serverLatencies) > 0 {
		bestServer := serverLatencies[0]
		return &bestServer.Server, bestServer.Latency, nil
	}
	return nil, 0, fmt.Errorf("no servers were successfully pinged")
}
