package mullvad

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

func GetClientIP(accountNumber, publicKey string) (string, error) {
	apiURL := "https://api.mullvad.net/wg/"
	data := url.Values{}
	data.Set("account", accountNumber)
	data.Set("pubkey", publicKey)

	resp, err := http.PostForm(apiURL, data)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("failed to fetch server info: status code %d, body: %s", resp.StatusCode, string(body))
	}

	clientIPs := strings.TrimSpace(string(body))
	ips := strings.Split(clientIPs, ",")
	if len(ips) < 1 {
		return "", fmt.Errorf("no IP addresses received from Mullvad API")
	}

	ipv4 := strings.Split(ips[0], "/")[0]
	return ipv4, nil
}
