package cli

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ALW1EZ/camtruder/pkg/config"
	"github.com/ALW1EZ/camtruder/pkg/credentials"
	"github.com/ALW1EZ/camtruder/pkg/scanner"
	"github.com/ALW1EZ/camtruder/pkg/utils"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/ALW1EZ/camtruder/pkg/ripe"
	"github.com/ALW1EZ/camtruder/pkg/media"
)

// Options represents command line options
type Options struct {
	Target    string
	UserInput string
	PassInput string
	Threads   int
	Timeout   int
	Output    string
	Verbose   bool
	Port      int
	SearchOnly bool
	SearchRaw  bool
	MediaDir   string // Directory to store screenshots
}

// ParseOptions parses command line flags and returns options
func ParseOptions() *Options {
	opts := &Options{}

	flag.Usage = func() {
		utils.DisplayBanner()
		fmt.Fprintf(os.Stderr, "%s", config.Usage)
	}

	flag.StringVar(&opts.Target, "t", "", "")
	flag.StringVar(&opts.UserInput, "u", "", "")
	flag.StringVar(&opts.PassInput, "p", "", "")
	flag.IntVar(&opts.Threads, "w", config.DefaultThreads, "")
	flag.IntVar(&opts.Timeout, "to", config.DefaultTimeout, "")
	flag.StringVar(&opts.Output, "o", "", "")
	flag.BoolVar(&opts.Verbose, "v", false, "")
	flag.BoolVar(&opts.SearchOnly, "s", false, "")
	flag.BoolVar(&opts.SearchRaw, "ss", false, "")
	flag.IntVar(&opts.Port, "po", config.DefaultPort, "")
	flag.StringVar(&opts.MediaDir, "m", "", "")
	flag.Parse()

	// Check for ffmpeg if screenshot directory is specified
	if opts.MediaDir != "" && !media.CheckFFmpegAvailable() {
		fmt.Printf("%sError: ffmpeg is required for taking screenshots but was not found in PATH%s\n",
			config.ColorRed, config.ColorReset)
		fmt.Printf("%sPlease install ffmpeg to use the screenshot feature (-m option)%s\n",
			config.ColorYellow, config.ColorReset)
		os.Exit(1)
	}

	return opts
}

// Run executes the scanner with the given options
func Run(opts *Options) error {
	// Configure gologger
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)

	// Get credentials list first
	var users, passwords []string
	if opts.UserInput != "" {
		users = credentials.ParseInput(opts.UserInput)
		if users == nil {
			return fmt.Errorf("invalid username input")
		}
	} else {
		users = credentials.DefaultUsers
	}

	if opts.PassInput != "" {
		passwords = credentials.ParseInput(opts.PassInput)
		if passwords == nil {
			return fmt.Errorf("invalid password input")
		}
	} else {
		passwords = credentials.DefaultPasswords
	}

	// Create output file if specified
	var outFile *os.File
	if opts.Output != "" {
		var err error
		outFile, err = os.Create(opts.Output)
		if err != nil {
			return fmt.Errorf("failed to create output file: %v", err)
		}
		defer outFile.Close()
	}

	// Process targets
	var targets []string
	if opts.Target == "" {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			flag.Usage()
			os.Exit(1)
		}
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			// Strip port if present in the input
			input := scanner.Text()
			if strings.Contains(input, ":") {
				input = strings.Split(input, ":")[0]
			}
			expanded := utils.ExpandCIDR(input)
			for _, ip := range expanded {
				targets = append(targets, utils.FormatIP(ip))
			}
		}
	} else {
		// Check if target is a number (limit for found cameras)
		if limit, err := strconv.Atoi(opts.Target); err == nil {
			return runInternetScan(limit, users, passwords, opts, outFile)
		} else if _, err := os.Stat(opts.Target); err == nil {
			// Reading from file
			lines := credentials.ParseInput(opts.Target)
			for _, line := range lines {
				expanded := utils.ExpandCIDR(line)
				for _, ip := range expanded {
					targets = append(targets, utils.FormatIP(ip))
				}
			}
		} else {
			// First try to parse as IP/CIDR
			expanded := utils.ExpandCIDR(opts.Target)
			if len(expanded) > 0 {
				// Successfully parsed as IP/CIDR
				if opts.SearchOnly || opts.Verbose {
					fmt.Printf("[ %s ] [ %s ] [%d]\n", "DIRECT_IP", opts.Target, len(expanded))
				}
				for _, ip := range expanded {
					targets = append(targets, utils.FormatIP(ip))
				}
			} else {
				// If not IP/CIDR, try location-based search
				ranges, err := ripe.SearchByLocation(opts.Target)
				if err == nil && len(ranges) > 0 {
					if opts.SearchRaw {
						// Print only raw CIDR ranges
						for _, ipRange := range ranges {
							startEnd := strings.Split(ipRange.Range, "-")
							if len(startEnd) == 2 {
								start := strings.TrimSpace(startEnd[0])
								end := strings.TrimSpace(startEnd[1])
								cidrRange := utils.RangeToCIDR(start, end)
								fmt.Println(cidrRange)
							} else {
								fmt.Println(ipRange.Range)
							}
						}
					} else if opts.SearchOnly || opts.Verbose {
						totalIPs := 0
						for _, ipRange := range ranges {
							startEnd := strings.Split(ipRange.Range, "-")
							if len(startEnd) == 2 {
								start := strings.TrimSpace(startEnd[0])
								end := strings.TrimSpace(startEnd[1])
								ips := utils.ExpandIPRange(start, end)
								totalIPs += len(ips)
								cidrRange := utils.RangeToCIDR(start, end)
								fmt.Printf("[ %s ] [ %s ] [%d]\n", ipRange.Netname, cidrRange, len(ips))
							} else {
								// Single IP
								totalIPs++
								fmt.Printf("[ %s ] [ %s ] [1]\n", ipRange.Netname, ipRange.Range)
							}
						}
					}

					// Process each range
					for _, ipRange := range ranges {
						startEnd := strings.Split(ipRange.Range, "-")
						if len(startEnd) == 2 {
							ips := utils.ExpandIPRange(strings.TrimSpace(startEnd[0]), strings.TrimSpace(startEnd[1]))
							for _, ip := range ips {
								targets = append(targets, utils.FormatIP(ip))
							}
						} else {
							targets = append(targets, utils.FormatIP(ipRange.Range))
						}
					}
				} else if opts.SearchOnly || opts.Verbose {
					if err != nil {
						fmt.Printf("%s Failed to search location: %v%s\n",
							config.ColorRed, err, config.ColorReset)
					} else {
						fmt.Printf("%s No IP ranges found for location: %s%s\n",
							config.ColorYellow, opts.Target, config.ColorReset)
					}
				}
			}

			// If search-only mode or raw search mode, exit after displaying results
			if opts.SearchOnly || opts.SearchRaw {
				return nil
			}
		}
	}

	if len(targets) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	return runTargetScan(targets, users, passwords, opts, outFile)
}

func runInternetScan(limit int, users, passwords []string, opts *Options, outFile *os.File) error {
	if opts.Verbose {
		fmt.Printf("%s Scanning internet until finding %d vulnerable cameras...%s\n",
			config.ColorBold, limit, config.ColorReset)
	}

	utils.DisplayInternetScanBanner(limit, len(users), len(passwords), opts.Threads, opts.Output)

	// Create scanner
	s := scanner.NewScanner(opts.Verbose, outFile, time.Duration(opts.Timeout)*time.Second, int32(limit), opts.MediaDir)

	for s.GetFoundCount() < int32(limit) {
		// Find IPs with open port
		if opts.Verbose {
			fmt.Printf("%s Searching for %d hosts with port %d open...%s\n",
				config.ColorBold, int32(limit)-s.GetFoundCount(), opts.Port, config.ColorReset)
		}
		targets := s.FindOpenPorts(int32(limit) - s.GetFoundCount())
		if opts.Verbose {
			fmt.Printf("%s Found %d hosts with port %d open%s\n",
				config.ColorBold, len(targets), opts.Port, config.ColorReset)
		}

		if len(targets) == 0 {
			continue
		}

		if err := scanTargets(targets, users, passwords, s, opts); err != nil {
			return err
		}
	}

	return nil
}

func runTargetScan(targets, users, passwords []string, opts *Options, outFile *os.File) error {
	utils.DisplayTargetBanner(len(targets), len(users), len(passwords), opts.Threads, opts.Output)

	// Create scanner
	s := scanner.NewScanner(opts.Verbose, outFile, time.Duration(opts.Timeout)*time.Second, 0, opts.MediaDir)

	return scanTargets(targets, users, passwords, s, opts)
}

func scanTargets(targets, users, passwords []string, s *scanner.Scanner, opts *Options) error {
	// Create work channel and wait group
	work := make(chan struct {
		IP   string
		Cred credentials.Credentials
		Path string
	})
	var wg sync.WaitGroup

	// Start worker threads
	actualThreads := opts.Threads
	if actualThreads > config.MaxParallelChecks {
		actualThreads = config.MaxParallelChecks
		fmt.Printf("%s Limiting parallel checks to %d for better performance%s\n",
			config.ColorYellow, config.MaxParallelChecks, config.ColorReset)
	}

	for i := 0; i < actualThreads; i++ {
		wg.Add(1)
		go s.Worker(work, &wg)
	}

	// Feed work
	for _, user := range users {
		for _, pass := range passwords {
			for _, ip := range targets {
				work <- struct {
					IP   string
					Cred credentials.Credentials
					Path string
				}{
					IP: ip,
					Cred: credentials.Credentials{
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

	return nil
}
