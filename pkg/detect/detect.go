package detect

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/go-ping/ping"
)

// MullvadServer represents a Mullvad VPN server.
type MullvadServer struct {
	Hostname    string `json:"hostname"`
	IPv4AddrIn  string `json:"ipv4_addr_in"`
	IPv6AddrIn  string `json:"ipv6_addr_in"`
	CountryName string `json:"country_name"`
}

// FetchMullvadServers fetches the list of Mullvad servers and filters them by country.
func FetchMullvadServers(country string) ([]MullvadServer, error) {
	resp, err := http.Get("https://api.mullvad.net/www/relays/all/")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var servers []MullvadServer
	err = json.Unmarshal(body, &servers)
	if err != nil {
		return nil, err
	}

	var filteredServers []MullvadServer
	for _, server := range servers {
		if server.CountryName == country {
			filteredServers = append(filteredServers, server)
		}
	}

	if len(filteredServers) == 0 {
		return nil, fmt.Errorf("no servers found for country: %s", country)
	}

	return filteredServers, nil
}

// PingServer pings a server to measure latency.
func PingServer(ip string) (time.Duration, error) {
	pinger, err := ping.NewPinger(ip)
	if err != nil {
		return 0, err
	}
	pinger.Count = 3
	pinger.Timeout = 2 * time.Second
	pinger.SetPrivileged(true)

	err = pinger.Run()
	if err != nil {
		return 0, err
	}

	stats := pinger.Statistics()
	return stats.AvgRtt, nil
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
			latency, err := PingServer(server.IPv4AddrIn)
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
