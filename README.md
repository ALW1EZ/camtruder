# 🎥 Camtruder

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.19+-00ADD8?style=flat-square&logo=go" alt="Go version">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blue?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/Version-3.0-green?style=flat-square" alt="Version">
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
  - Pipe input support (zmap integration)
  - Internet-wide scanning with customizable limits
  - Intelligent port discovery

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
  - Custom path testing support

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
  - JSON output support

## 📋 Requirements

- Go 1.19 or higher
- Internet connection
- Root/Administrator privileges (for certain scanning modes)
- Sufficient system resources for large-scale scans

## 🔧 Installation

```bash
# Clone the repository
git clone https://github.com/ALW1EZ/camtruder.git

# Navigate to the directory
cd camtruder

# Build the binary
go build -o camtruder

# Make it executable (Linux/macOS)
chmod +x camtruder
```

## 🚀 Usage

### Basic Commands

```bash
# Scan a single IP
./camtruder -t 192.168.1.100

# Scan a network range
./camtruder -t 192.168.1.0/24

# Scan multiple IPs from file
./camtruder -t targets.txt

# Pipe from zmap
zmap -p554 192.168.0.0/16 | ./camtruder
```

### Advanced Options

```bash
# Custom credentials with increased threads
./camtruder -t 192.168.1.0/24 -u admin,root -p pass123,admin123 -w 50

# Verbose output with custom timeout
./camtruder -t 192.168.1.0/24 -v -to 10

# Save results to file
./camtruder -t 192.168.1.0/24 -o results.txt

# Internet scan with limit
./camtruder -t 100 -w 50 -v
```

## 🛠️ Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-t` | Target IP, CIDR range, or file | Required |
| `-u` | Custom username(s) | Built-in list |
| `-p` | Custom password(s) | Built-in list |
| `-w` | Number of threads | 20 |
| `-to` | Connection timeout (seconds) | 3 |
| `-o` | Output file path | None |
| `-v` | Verbose output | False |

## 🎯 Features in Detail

### Authentication Testing
- Default credential database
- Support for multiple authentication formats
- Custom credential list support
- Intelligent credential validation

### Path Discovery
- Comprehensive vendor path database
- Dynamic path generation
- Path validation system
- Custom path testing

### Performance Optimization
- Multi-threaded architecture
- Smart connection handling
- Resource management
- Efficient retry mechanisms

### Output & Analysis
- Real-time progress display
- Detailed logging
- Camera fingerprinting
- Stream analysis
- Result export

## 📊 Output Format

```plaintext
╭─ Found vulnerable camera [Hikvision, H264, 30fps]
├ Host      : 192.168.1.100:554
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