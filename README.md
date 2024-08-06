# Camtruder 🕵️‍♂️

![2024-08-07_00-10](https://github.com/user-attachments/assets/799c7b39-c16d-49b1-b87e-8360cbd4e8bf)


*by: @alw1ez*  
*Version: 1.0*

## Overview

Camtruder is a powerful tool designed for testing the security of RTSP (Real-Time Streaming Protocol) streams. It allows users to perform brute-force attacks on RTSP servers to discover valid credentials and check for accessible routes. This tool is intended for educational purposes and should only be used in environments where you have explicit permission to test.

## Features

- **Brute-force Authentication**: Test multiple username and password combinations against RTSP servers.
- **Route Detection**: Identify accessible RTSP routes on authenticated streams.
- **Concurrency**: Supports multiple threads for faster execution.
- **Output Logging**: Save results to specified output files for further analysis.
- **Verbose Logging**: Adjustable verbosity levels for detailed output.
- **Supports Stdin Inputs**: Accepts input from standard input for IPs via pipe.
- **Authentication Methods**: Supports both Basic and Digest authentication.

## Requirements

- Go (version 1.16 or higher)
- `ffplay` for stream testing

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/ALW1EZ/camtruder.git
   cd camtruder
   ```

2. Build the project:
   ```bash
   go build -o camtruder main.go
   ```

3. Ensure `ffplay` is installed and accessible in your system's PATH.
It comes with `ffmpeg` which is always installed on Linux distributions by default. If you don't you can install 
with `sudo apt install ffmpeg`, without this route detection won't work.

## Usage

```bash
./camtruder -t <target_file_or_ip> -u <username_file_or_username> -p <password_file_or_password> [-r <routes_file_or_route>] [-o <output_file>] [-or <output_route_file>] [-c <threads>] [-ct <route_threads>] [-v <verbosity>] [-to <timeout>] [-tr <max_retries>]
```

### Flags

- `-h`: Show help
- `-port`: Specify the RTSP port to scan (default: 554)
- `-t`: Path to a file containing target IPs or a single IP address (supports stdin)
- `-u`: Path to a file containing usernames or a single username
- `-p`: Path to a file containing passwords or a single password
- `-r`: Path to a file containing RTSP routes or a single RTSP route
- `-o`: Path to an output file where credential results will be saved
- `-or`: Path to an output file where route results will be saved
- `-c`: Number of concurrent threads to use during the attack (default: 200)
- `-ct`: Number of concurrent threads to use during the route detection (default: 3)
- `-v`: Set verbosity level (1 for warnings, 2 for errors, 3 for debugging)
- `-to`: Connection timeout duration in seconds (default: 3)
- `-tr`: Maximum number of retries for each connection (default: 3)

### Examples

- **Help**:
  ```bash
  ./camtruder -h
  ```

- **Single IP with no authentication**:
  ```bash
  ./camtruder -t xxx.xxx.xx.xxx
  ```

- **Multiple IPs from a file**:
  ```bash
  ./camtruder -t ip_file.txt
  ```

- **Using stdin for IP input**:
Both xxx.xxx.xx.xxx and xxx.xxx.xx.xxx:port, inputs are allowed for stdin and file input.
You can pipe, zmap or naabu output to camtruder.
  ```bash
  echo 1.1.1.1 | ./camtruder
  cat ips.txt | ./camtruder
  ```
  ips.txt:
    ```text
  xxx.xxx.xx.xxx
  xxx.xxx.xxx.xx:8554
  xx.xxx.xx.xxx:554
  ```

- **Using username and password files**:
  ```bash
  ./camtruder -t targets.txt -u usernames.txt -p passwords.txt
  ```
    ```bash
  ./camtruder -t targets.txt -u admin -p passwords.txt
  ```
    ```bash
  ./camtruder -t xxx.xxx.xx.xxx -u usernames.txt -p admin123456
  ```

- **Route detection with output files**:
  ```bash
  ./camtruder -t targets.txt -u usernames.txt -p passwords.txt -r routes.txt -o results.txt -or routes_results.txt
  ```

### Accessing Streams

To access the streams, you can use `mpv`, `ffplay`, or `vlc`. It is recommended to try `mpv` first. For multiple streams, you can create a playlist:

```bash
mpv --playlist=route_output.txt
```

## Contributing

Contributions are welcome! If you have suggestions for improvements or new features, feel free to open an issue or submit a pull request.

## Disclaimer

This tool is intended for educational purposes only. Use it responsibly and only on networks and systems you own or have explicit permission to test. The author is not responsible for any misuse of this tool.

## Thanks

Thanks to ![@Ullaakut](https://github.com/Ullaakut/) for his project ![Cameradar](https://github.com/Ullaakut/cameradar), and directories folder, helped a lot.

Thanks to ![@projectdiscovery](https://github.com/projectdiscovery/) for this beautiful ![gologger](https://github.com/projectdiscovery/gologger) library.

Thanks to ![icholy](https://github.com/icholy/) for ![digest](https://github.com/icholy/digest) library.

Thanks to ![@common-nighthawk](https://github.com/common-nighthawk/) for ![go-figure](https://github.com/common-nighthawk/go-figure) library, hard-coded ASCII arts really stresses me out.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
