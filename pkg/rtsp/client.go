package rtsp

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/bluenviron/gortsplib/v4"
	"github.com/bluenviron/gortsplib/v4/pkg/base"
	"github.com/bluenviron/gortsplib/v4/pkg/description"
	"github.com/bluenviron/gortsplib/v4/pkg/format"
	"github.com/pion/rtp"
)

// TestResult represents the result of testing RTSP credentials
type TestResult struct {
	Success  bool
	Response string
	Error    error
}

// TestCredentials tests RTSP credentials against a URL
func TestCredentials(rtspURL string, timeout time.Duration, verbose bool) (bool, string) {
	client := &gortsplib.Client{
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
		// Ignore SSRC validation errors
		OnDecodeError: func(err error) {
			if !strings.Contains(err.Error(), "SSRC") {
				if verbose {
					fmt.Printf("Decode error: %v\n", err)
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

// GetFingerprint analyzes the response and URL to determine camera characteristics
func GetFingerprint(response string, url string) string {
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
