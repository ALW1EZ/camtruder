# 🎥 Camtruder

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.19+-00ADD8?style=flat-square&logo=go" alt="Go version">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blue?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/Version-3.7-green?style=flat-square" alt="Version">
</p>

<p align="center">
  <b>Advanced RTSP Camera Discovery and Vulnerability Assessment Tool</b>
</p>

Camtruder is a high-performance RTSP camera discovery and vulnerability assessment tool written in Go. It efficiently scans and identifies vulnerable RTSP cameras across networks using various authentication methods and path combinations, with support for both targeted and internet-wide scanning capabilities.

## 🌟 Key Features

- **Advanced Scanning Capabilities**
  - Single IP targeting
  - CIDR range scanning
  - File-based target lists
  - Pipe input support
  - Internet-wide scanning with customizable limits
  - Intelligent port discovery
  - Location-based search using RIPE database
  - Raw CIDR output for integration with other tools

- **Screenshot Capability**
  - Capture screenshots of discovered cameras
  - Automatic saving of JPEG images
  - Requires ffmpeg installation
  - Configurable output directory

- **Location-Based Search**
  - Search by city or country name
  - RIPE database integration
  - Detailed output with netnames and IP ranges
  - CIDR notation support
  - Raw output mode for scripting

- **Comprehensive Authentication Testing**
  - Built-in common credential database
  - Custom username/password list support
  - File-based credential input
  - Multiple authentication format handling
  - Credential validation system

- **Smart Path Discovery**
  - Extensive default path database
  - Vendor-specific path detection
  - Dynamic path generation
  - Automatic path validation

- **High Performance Architecture**
  - Multi-threaded scanning engine
  - Configurable connection timeouts
  - Efficient resource management
  - Smart retry mechanisms
  - Parallel connection handling

- **Advanced Output & Analysis**
  - Real-time console feedback
  - Detailed logging system
  - Camera fingerprinting
  - Vendor detection
  - Stream capability analysis
  - Multiple output formats (verbose, raw)

## 📋 Requirements

- Go 1.19 or higher
- ffmpeg (required for screenshot functionality)
- Internet connection
- Root/Administrator privileges (for certain scanning modes)
- Sufficient system resources for large-scale scans

## 🔧 Installation

### Using go install (recommended)
```bash
go install github.com/ALW1EZ/camtruder@v3.7.0
```

### From source
```bash
git clone https://github.com/ALW1EZ/camtruder.git
cd camtruder
go build
```

## 🚀 Usage

### Basic Commands

```bash
# Scan a single IP
./camtruder -t 192.168.1.100

# Scan a network range
./camtruder -t 192.168.1.0/24

# Search by location with detailed output
./camtruder -t london -s
> [ NET-ISP ] [ 192.168.1.0/24 ] [256]

# Get raw CIDR ranges for location
./camtruder -t london -ss
> 192.168.1.0/24

# Scan multiple IPs from file
./camtruder -t targets.txt

# Take screenshots of discovered cameras
./camtruder -t 192.168.1.0/24 -m screenshots

# Pipe from port scanners
naabu -host 192.168.1.0/24 -p 554 | camtruder
masscan 192.168.1.0/24 -p554 --rate 1000 | awk '{print $6}' | camtruder
zmap -p554 192.168.0.0/16 | camtruder

# Internet scan (scan till 100 hits)
./camtruder -t 100
```

### Advanced Options

```bash
# Custom credentials with increased threads
./camtruder -t 192.168.1.0/24 -u admin,root -p pass123,admin123 -w 50

# Location search with raw output piped to zmap
./camtruder -t berlin -ss | while read range; do zmap -p 554 $range; done

# Save results to file (as full url, you can use mpv --playlist=results.txt to watch the streams)
./camtruder -t istanbul -o results.txt

# Internet scan with limit of 50 workers and verbose output
./camtruder -t 100 -w 50 -v
```

## 🛠️ Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-t` | Target IP, CIDR range, location, or file | Required |
| `-u` | Custom username(s) | Built-in list |
| `-p` | Custom password(s) | Built-in list |
| `-w` | Number of threads | 20 |
| `-to` | Connection timeout (seconds) | 5 |
| `-o` | Output file path | None |
| `-v` | Verbose output | False |
| `-s` | Search only - shows ranges with netnames | False |
| `-ss` | Raw IP range output - only CIDR ranges | False |
| `-po` | RTSP port | 554 |
| `-m` | Directory to save screenshots (requires ffmpeg) | None |

## 📊 Output Formats

### Standard Search Output (-s)
```plaintext
[ TR-NET-ISP ] [ 193.3.52.0/24 ] [256]
[ EXAMPLE-ISP ] [ 212.175.100.136/29 ] [8]
```

### Raw CIDR Output (-ss)
```plaintext
193.3.52.0/24
212.175.100.136/29
```

### Scan Results
```plaintext
╭─ Found vulnerable camera [Hikvision, H264, 30fps]
├ Host      : 192.168.1.100:554
├ Geo       : United States/California/Berkeley
├ Auth      : admin:12345
├ Path      : /Streaming/Channels/1
╰ URL       : rtsp://admin:12345@192.168.1.100:554/Streaming/Channels/1
```

## ⚠️ Disclaimer

This tool is intended for security research and authorized testing only. Users are responsible for ensuring they have permission to scan target systems and comply with all applicable laws and regulations.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Thanks to all contributors and the security research community
- Special thanks to the Go RTSP library maintainers
- Inspired by various open-source security tools

## 📬 Contact

- Author: @ALW1EZ
- Project Link: [https://github.com/ALW1EZ/camtruder](https://github.com/ALW1EZ/camtruder)

---
<p align="center">Made by @ALW1EZ</p>