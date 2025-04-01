package media

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// CheckFFmpegAvailable checks if ffmpeg is available in the system
func CheckFFmpegAvailable() bool {
	_, err := exec.LookPath("ffmpeg")
	return err == nil
}

// formatRTSPComponents extracts and formats components from RTSP URL
func formatRTSPComponents(rtspURL string) string {
	u, err := url.Parse(rtspURL)
	if err != nil {
		return "invalid_url" // fallback for invalid URLs
	}

	// Extract username and password
	username := ""
	password := ""
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
	}

	// Extract host and port
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "554" // default RTSP port
	}

	// Format as username@password:ip:port
	return fmt.Sprintf("%s@%s:%s:%s", username, password, host, port)
}

// TakeScreenshot captures a screenshot from an RTSP stream using ffmpeg and saves it to the specified directory
func TakeScreenshot(rtspURL string, outputDir string, timeout time.Duration) error {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Create filename with timestamp and RTSP components
	timestamp := time.Now().Format("20060102_150405")
	rtspComponents := formatRTSPComponents(rtspURL)
	filename := filepath.Join(outputDir, fmt.Sprintf("%s_%s.jpg", rtspComponents, timestamp))

	// Prepare ffmpeg command
	// -y: overwrite output file
	// -rtsp_transport tcp: use TCP for RTSP (more reliable)
	// -frames:v 1: capture only one frame
	cmd := exec.Command("ffmpeg",
		"-y",
		"-rtsp_transport", "tcp",
		"-i", rtspURL,
		"-frames:v", "1",
		"-loglevel", "error", // only show errors
		filename)

	// Set timeout
	cmd.WaitDelay = timeout

	// Run command and capture any error output
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to capture screenshot: %v (%s)", err, string(output))
	}

	return nil
} 