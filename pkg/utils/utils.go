package utils

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ALW1EZ/camtruder/pkg/config"
	"github.com/common-nighthawk/go-figure"
	"bytes"
)

type GeoIPResponse struct {
	City      string  `json:"city"`
	Country   string  `json:"country"`
	IP        string  `json:"ip"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	State     string  `json:"state"`
}

// GetGeoLocation returns the geolocation information for an IP address
func GetGeoLocation(ip string) string {
	// Remove port if present
	if strings.Contains(ip, ":") {
		ip = strings.Split(ip, ":")[0]
	}

	url := fmt.Sprintf("https://api.hackertarget.com/geoip/?q=%s&output=json", ip)
	resp, err := http.Get(url)
	if err != nil {
		return "Unknown Location"
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "Unknown Location"
	}

	var geoIP GeoIPResponse
	if err := json.Unmarshal(body, &geoIP); err != nil {
		return "Unknown Location"
	}

	// Build location string
	var location []string
	if geoIP.Country != "" {
		location = append(location, geoIP.Country)
	}
	if geoIP.State != "" {
		location = append(location, geoIP.State)
	}
	if geoIP.City != "" {
		location = append(location, geoIP.City)
	}

	if len(location) == 0 {
		return "Unknown Location"
	}

	return strings.Join(location, "/")
}

// DisplayBanner displays the main application banner
func DisplayBanner() {
	fmt.Print(figure.NewFigure("     camtruder", "cybermedium", true))
	println()
	fmt.Printf("%s\t\t\t%s v3.7%s by @ALW1EZ\n", config.ColorYellow, config.ColorBold, config.ColorReset)
	fmt.Printf("\t\t   %sRTSP Camera Assessment Tool%s\n", config.ColorBlue, config.ColorReset)
	fmt.Println(config.ColorPurple + strings.Repeat("─", 67) + config.ColorReset)
}

// DisplayTargetBanner displays the banner with target information
func DisplayTargetBanner(targets, users, passwords, threads int, output string) {
	DisplayBanner()
	fmt.Printf("%s Targets: %d | Users: %d | Passwords: %d | Threads: %d%s%s\n",
		config.ColorBold, targets, users, passwords, threads, getOutputStr(output), config.ColorReset)
	println()
}

// DisplayInternetScanBanner displays the banner for internet scanning
func DisplayInternetScanBanner(limit, users, passwords, threads int, output string) {
	DisplayBanner()
	fmt.Printf("%s Internet Scan | Limit: %d | Users: %d | Passwords: %d | Threads: %d%s%s\n",
		config.ColorBold, limit, users, passwords, threads, getOutputStr(output), config.ColorReset)
	println()
}

func getOutputStr(output string) string {
	if output != "" {
		return fmt.Sprintf("\n Output : %s", output)
	}
	return ""
}

// FormatIP formats an IP address with port
func FormatIP(ip string) string {
	if strings.Contains(ip, ":") {
		return ip
	}
	return fmt.Sprintf("%s:%d", ip, config.DefaultPort)
}

// FormatIPBytes formats IP bytes with port
func FormatIPBytes(ip []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d:%d", ip[0], ip[1], ip[2], ip[3], config.DefaultPort)
}

// ExpandCIDR expands a CIDR range into individual IP addresses
func ExpandCIDR(cidr string) []string {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		// Try parsing as a single IP
		if net.ParseIP(cidr) != nil {
			return []string{cidr}
		}
		return []string{} // Return empty slice for invalid input
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast address
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips
}

// IncrementIP increments an IP address
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// GenerateRandomIP generates a random IP address avoiding reserved ranges
func GenerateRandomIP() string {
	for {
		ip := make([]byte, 4)
		_, err := rand.Read(ip)
		if err != nil {
			continue
		}

		// Skip private, loopback, multicast ranges
		if ip[0] == 10 || // 10.0.0.0/8
			(ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) || // 172.16.0.0/12
			(ip[0] == 192 && ip[1] == 168) || // 192.168.0.0/16
			ip[0] == 127 || // 127.0.0.0/8
			ip[0] == 0 || // 0.0.0.0/8
			ip[0] == 169 && ip[1] == 254 || // 169.254.0.0/16
			ip[0] >= 224 || // 224.0.0.0/4 and above
			ip[0] == 192 && ip[1] == 0 && ip[2] == 2 { // 192.0.2.0/24
			continue
		}

		return fmt.Sprintf("%d.%d.%d.%d:554", ip[0], ip[1], ip[2], ip[3])
	}
}

// ScanPort checks if a port is open on a given IP
func ScanPort(ip string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", ip, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// WriteResult writes a result to a file if the file is not nil
func WriteResult(result string, outFile *os.File) {
	if outFile != nil {
		fmt.Fprintln(outFile, result)
	}
}

// ExpandIPRange expands an IP range from start to end into individual IPs
func ExpandIPRange(start, end string) []string {
	startIP := net.ParseIP(start).To4()
	endIP := net.ParseIP(end).To4()
	if startIP == nil || endIP == nil {
		return nil
	}

	var ips []string
	for ip := startIP; bytes.Compare(ip, endIP) <= 0; incrementIP(ip) {
		ips = append(ips, ip.String())
	}
	return ips
}

// RangeToCIDR converts an IP range (start-end) to CIDR notation
func RangeToCIDR(start, end string) string {
	startIP := net.ParseIP(start).To4()
	endIP := net.ParseIP(end).To4()
	if startIP == nil || endIP == nil {
		return fmt.Sprintf("%s-%s", start, end)
	}

	// If start and end are the same, return as single IP
	if bytes.Equal(startIP, endIP) {
		return start
	}

	// Convert IPs to 32-bit integers for easier comparison
	startInt := ipToUint32(startIP)
	endInt := ipToUint32(endIP)

	for prefix := uint32(32); prefix > 0; prefix-- {
		mask := uint32(0xFFFFFFFF) << (32 - prefix)
		networkStart := startInt & mask
		networkEnd := networkStart | (^mask)
		
		if networkStart == startInt && networkEnd == endInt {
			return fmt.Sprintf("%s/%d", start, prefix)
		}
	}

	// If no exact CIDR match found, return original range
	return fmt.Sprintf("%s-%s", start, end)
}

// ipToUint32 converts an IP address to a 32-bit unsigned integer
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}
