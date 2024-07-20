package detect

import (
	"encoding/json"
	"fmt"
	"io"
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
	PublicKey   string `json:"pubkey"`
	Type        string `json:"type"`
	Latency     time.Duration
}

// FetchAllMullvadServers fetches the list of all Mullvad servers.
func FetchAllMullvadServers() ([]MullvadServer, error) {
	url := "https://api.mullvad.net/www/relays/all/"
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	var servers []MullvadServer
	err = json.Unmarshal(body, &servers)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshaling failed: %v", err)
	}

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

// ServerLatency holds the latency information of a server.
type ServerLatency struct {
	Server  MullvadServer
	Latency time.Duration
}

// TCPPing pings a server to measure latency.
func TCPPing(ip string, port int) (time.Duration, error) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 500*time.Millisecond)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	return time.Since(start), nil
}

// FindBestServers finds the best Mullvad servers based on latency.
func FindBestServers(count int) ([]MullvadServer, error) {
	servers, err := FetchAllMullvadServers()
	if err != nil {
		return nil, err
	}

	results := make(chan ServerLatency, len(servers))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 50)

	for _, server := range servers {
		wg.Add(1)
		go func(server MullvadServer) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			latency, err := TCPPing(server.IPv4AddrIn, 443)
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

	if len(serverLatencies) == 0 {
		return nil, fmt.Errorf("no servers were successfully pinged")
	}

	sort.Slice(serverLatencies, func(i, j int) bool {
		return serverLatencies[i].Latency < serverLatencies[j].Latency
	})

	if count > len(serverLatencies) {
		count = len(serverLatencies)
	}

	var bestServers []MullvadServer
	for i := 0; i < count; i++ {
		bestServers = append(bestServers, serverLatencies[i].Server)
	}

	return bestServers, nil
}

// FindBestServersInCountry finds the best Mullvad servers in a specific country based on latency.
func FindBestServersInCountry(countryCode string, count int) ([]MullvadServer, error) {
	servers, err := FetchAllMullvadServers()
	if err != nil {
		return nil, err
	}

	var countryServers []MullvadServer
	for _, server := range servers {
		if strings.EqualFold(server.CountryName, countryCode) {
			countryServers = append(countryServers, server)
		}
	}

	if len(countryServers) == 0 {
		return nil, fmt.Errorf("no servers found in specified country: %s", countryCode)
	}

	results := make(chan ServerLatency, len(countryServers))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 50)

	for _, server := range countryServers {
		wg.Add(1)
		go func(server MullvadServer) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			latency, err := TCPPing(server.IPv4AddrIn, 443)
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

	if len(serverLatencies) == 0 {
		return nil, fmt.Errorf("no servers were successfully pinged")
	}

	sort.Slice(serverLatencies, func(i, j int) bool {
		return serverLatencies[i].Latency < serverLatencies[j].Latency
	})

	if count > len(serverLatencies) {
		count = len(serverLatencies)
	}

	var bestServers []MullvadServer
	for i := 0; i < count; i++ {
		bestServers = append(bestServers, serverLatencies[i].Server)
	}

	return bestServers, nil
}

// SelectBestServer selects the best Mullvad server based on the given configuration.
func SelectBestServer(serverName, countryCode string, useLatencyBasedSelection bool) (*MullvadServer, error) {
	var bestServers []MullvadServer
	var err error

	switch {
	case serverName != "":
		bestServers, err = FetchAllMullvadServers()
		if err != nil {
			return nil, fmt.Errorf("failed to fetch Mullvad servers: %v", err)
		}
		for _, server := range bestServers {
			if server.Hostname == serverName {
				return &server, nil
			}
		}
		return nil, fmt.Errorf("specified server %s not found", serverName)

	case countryCode != "":
		bestServers, err = FindBestServersInCountry(countryCode, 1)
		if err != nil {
			return nil, fmt.Errorf("failed to find best server in country: %v", err)
		}
		if len(bestServers) > 0 {
			return &bestServers[0], nil
		}

	case useLatencyBasedSelection:
		bestServers, err = FindBestServers(1)
		if err != nil {
			return nil, fmt.Errorf("failed to find best server: %v", err)
		}
		if len(bestServers) > 0 {
			return &bestServers[0], nil
		}
	}

	return nil, fmt.Errorf("no server selected")
}
