package config

// Constants for colors
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
	ColorBold   = "\033[1m"
)

// Default configuration values
const (
	DefaultTimeout    = 5
	DefaultThreads    = 20
	MaxParallelChecks = 1000
	DefaultPort       = 554
)

// Default paths for RTSP streams
var DefaultPaths = []string{
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

	// Credential-based paths
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

// Usage information
const Usage = `
Usage:
  Single IP:     camtruder -t 192.168.1.100
  IP Range:      camtruder -t 192.168.1.0/24
  Location:      camtruder -t london
  Multiple IPs:  camtruder -t ips.txt
  From pipe:     zmap -p8554 -N 10 | camtruder -po 8554
  Internet scan: camtruder -t 100

Options:
  -t  <ip/file/loc>  Target IP, CIDR range, location, or file with IPs
  -u  <input>        Custom username(s) [file or comma separated list]
  -p  <input>        Custom password(s) [file or comma separated list]
  -w  <num>          Number of threads (default: 20)
  -to <seconds>      Timeout (default: 5)
  -po <port>         RTSP port (default: 554)
  -o  <file>         Output file
  -v                 Verbose output
  -s                 Search only mode - shows ranges with netnames
  -ss                Raw IP range output - only CIDR ranges, one per line
  -m  <dir>          Directory to save camera screenshots

Examples:
  # Scan single IP with default credentials
  camtruder -t 192.168.1.100

  # Scan network range with custom credentials
  camtruder -t 192.168.1.0/24 -u admin,root -p pass123,admin123

  # Search location and show ranges with netnames
  camtruder -t london -s
  > [ TR-NET-ISP ] [ 193.3.52.0/24 ] [256]

  # Get raw CIDR ranges for piping to other tools
  camtruder -t london -ss
  > 193.3.52.0/24

  # Pipe raw ranges to zmap
  camtruder -t london -ss | while read range; do zmap -p 554 $range; done

  # Scan IPs from file with increased threads
  camtruder -t targets.txt -w 50

  # Scan from zmap output with custom timeout and port
  zmap -p8554 192.168.0.0/16 | camtruder -to 10 -po 8554

  # Save results to file with verbose output
  camtruder -t istanbul -o results.txt -v

  # Scan and save screenshots of found cameras
  camtruder -t 192.168.1.0/24 -m screenshots
`
