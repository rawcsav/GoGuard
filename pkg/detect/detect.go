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
	Type        string `json:"type"`
}

// FetchAllMullvadServers retrieves all Mullvad servers and filters for WireGuard servers.
func FetchAllMullvadServers() ([]MullvadServer, error) {
	url := "https://api.mullvad.net/www/relays/all/"
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	var servers []MullvadServer
	err = json.Unmarshal(body, &servers)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshaling failed: %v", err)
	}

	// Filter to keep only WireGuard servers
	var wireguardServers []MullvadServer
	for _, server := range servers {
		if strings.ToLower(server.Type) == "wireguard" {
			wireguardServers = append(wireguardServers, server)
		}
	}

	if len(wireguardServers) == 0 {
		return nil, fmt.Errorf("no WireGuard servers found")
	}

	return wireguardServers, nil
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

// ServerLatency represents a server and its measured latency.
type ServerLatency struct {
	Server  MullvadServer
	Latency time.Duration
}

// FindBestServer finds the Mullvad WireGuard server with the lowest latency.
func FindBestServer() (*MullvadServer, time.Duration, error) {
	servers, err := FetchAllMullvadServers()
	if err != nil {
		return nil, 0, err
	}

	results := make(chan ServerLatency)
	var wg sync.WaitGroup
	totalServers := len(servers)
	fmt.Printf("Pinging %d servers\n", totalServers)

	for _, server := range servers {
		wg.Add(1)
		go func(server MullvadServer) {
			defer wg.Done()
			latency, err := TCPPing(server.IPv4AddrIn, 443) // WireGuard typically uses port 51820
			if err != nil {
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
