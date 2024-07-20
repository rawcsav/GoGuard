# GoGuard

GoGuard is a Go-based VPN client that interfaces with Mullvad's WireGuard servers. It allows users to connect to the best available server based on latency, country, or a specific server. The client also supports custom DNS settings and includes monitoring to ensure continuous connectivity.

## Features

- **Server Selection**: Automatically selects the best server based on latency, country, or a specific server.
- **DNS Configuration**: Ability to customize DNS servers.
- **Key Management**: Generates or uses existing WireGuard private keys.
- **Pre/Post Commands**: Ability to specify custom commands to run before and after the VPN connection is established or terminated.
- **Connection Monitoring**: Monitors VPN connection and switch servers if a lapse in connection is detected.
- **Configuration Management**: Uses [Viper](https://github.com/spf13/viper) for flexible configuration management with support for environment variables and YAML configuration files.

## Installation

### Prerequisites

- Go 1.16 or later
- WireGuard tools (`wg`, `wg-quick`)
- `sudo` privileges for network configuration
- A Mullvad account and account #

### Steps

1. Clone the repository:
    ```sh
    git clone https://github.com/rawcsav/GoGuard.git
    cd GoGuard
    ```

2. Build the project:
    ```sh
    go build -o gogguard cmd/goguard/main.go

    ```

3. Ensure `wg` and `wg-quick` are installed and accessible in your PATH.

## Configuration

GoGuard uses a YAML configuration file for its settings. Below is an example configuration file (`config.yaml`):

```yaml
mullvad_account_number: "your mullvad account number"
interface_name: "wg0"
server_name: ""
country_code: "us"
use_latency_based_selection: true
dns:
  - "10.64.0.1"
pre_up: []
post_up: []
pre_down: []
post_down: []
```

### Optional Command-Line Flags
These will override the config.yaml settings:

- `-config`: Path to the configuration file (default: `config.yaml`)
- `-server`: WireGuard server to connect to (e.g., `se-mma-wg-001`)
- `-country`: Country code for server selection
- `-dns`: DNS server to use (comma-separated)
- `-latency`: Use latency-based server selection

## Usage

1. Run GoGuard with the desired configuration:
    ```sh
    ./goguard
    ```

2. To specify command-line flags:
    ```sh
    ./goguard -server=se-mma-wg-001 -dns=1.1.1.1,8.8.8.8 -latency
    ```

## Development Status

**Note:** GoGuard is currently in active development. While it is functional, it is not yet considered stable for production use. 
I will be continuously working on improving the core functionality/adding new features. 
However, this is my first Go project, and I am certainly learning as I go.
Contributions and feedback are highly appreciated.

### Next Steps

The following are the next steps for the GoGuard project, as outlined in the recent commit message:

1. **More Customization**:
   - Implement additional features such as multihop, SOCKS5 proxy, and other Mullvad options.

2. **Project Structure and Organization**:
   - Flesh out the project structure and organization to ensure maintainability and scalability.
   - Improve logging to provide better insights and debugging information.

3. **Network Settings**:
   - Revisit network settings to ensure that the current functions for route and DNS tunneling are necessary for Linux runtimes.
   - Determine if `wg-quick` makes some of these settings trivial and adjust accordingly.

4. **Robustness**:
   - Ensure the robustness of the application to allow it to sit in front of the WireGuard connection and adapt the connection in case of unexpected downtime.
   - Implement mechanisms to handle connection lapses and automatically switch to the best available server.

5. **Go Optimization**:
   - Ensure that Go is used properly and optimized throughout the project.
   - Capitalize on the language's strengths, such as concurrency and per

## License

GoGuard is licensed under the Attribution-ShareAlike 4.0 International License. 
See the [LICENSE](LICENSE) file for more information.

## Acknowledgements
- [Mullvad VPN](https://mullvad.net/) for their excellent VPN service and API.
- [WireGuard](https://www.wireguard.com/) for the VPN protocol.