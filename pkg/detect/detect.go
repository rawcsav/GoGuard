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

type ServerLatency struct {
	Server  MullvadServer
	Latency time.Duration
}

func TCPPing(ip string, port int) (time.Duration, error) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 500*time.Millisecond)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	return time.Since(start), nil
}

// FindBestServer finds the Mullvad WireGuard server with the lowest latency
func FindBestServer() (*MullvadServer, time.Duration, error) {
	servers, err := FetchAllMullvadServers()
	if err != nil {
		return nil, 0, err
	}

	results := make(chan ServerLatency, len(servers))
	var wg sync.WaitGroup

	// Increase concurrent goroutines, but still limit them
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
		return nil, 0, fmt.Errorf("no servers were successfully pinged")
	}

	sort.Slice(serverLatencies, func(i, j int) bool {
		return serverLatencies[i].Latency < serverLatencies[j].Latency
	})

	// Take the top 10% of servers and perform additional pings
	topServers := int(float64(len(serverLatencies)) * 0.1)
	if topServers < 5 {
		topServers = 5 // Ensure at least 5 servers for the second round
	}

	var finalResults []ServerLatency
	for i := 0; i < topServers && i < len(serverLatencies); i++ {
		server := serverLatencies[i].Server
		totalLatency := time.Duration(0)
		successfulPings := 0

		for j := 0; j < 3; j++ {
			latency, err := TCPPing(server.IPv4AddrIn, 443)
			if err == nil {
				totalLatency += latency
				successfulPings++
			}
		}

		if successfulPings > 0 {
			avgLatency := totalLatency / time.Duration(successfulPings)
			finalResults = append(finalResults, ServerLatency{Server: server, Latency: avgLatency})
		}
	}

	if len(finalResults) == 0 {
		return nil, 0, fmt.Errorf("no servers passed the final ping test")
	}

	sort.Slice(finalResults, func(i, j int) bool {
		return finalResults[i].Latency < finalResults[j].Latency
	})

	bestServer := finalResults[0]
	return &bestServer.Server, bestServer.Latency, nil
}
