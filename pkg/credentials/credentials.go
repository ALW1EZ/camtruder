package credentials

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

// Credentials represents a username/password pair
type Credentials struct {
	Username string
	Password string
}

// Default credential lists
var (
	DefaultUsers = []string{
		"admin", "root", "service", "supervisor", "user",
		"Admin", "administrator", "666666", "888888",
	}

	DefaultPasswords = []string{
		"", "admin", "12345", "123456", "1234", "12345678", "admin123", "root", "password",
		"pass", "root123",
	}
)

// ParseInput parses input string into a slice of strings
// Input can be either a comma-separated list or a file path
func ParseInput(input string) []string {
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

// readLines reads a file and returns non-empty lines
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

// ReplaceCreds replaces credential placeholders in paths
func ReplaceCreds(path, username, password string) string {
	path = strings.ReplaceAll(path, "usrnm:pwd", username+":"+password)
	path = strings.ReplaceAll(path, "user=admin&password=", fmt.Sprintf("user=%s&password=%s", username, password))
	return path
}
