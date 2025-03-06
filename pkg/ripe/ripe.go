package ripe

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type RIPEResponse struct {
	XMLName xml.Name `xml:"response"`
	Result  struct {
		XMLName   xml.Name `xml:"result"`
		NumFound  int      `xml:"numFound,attr"`
		Documents []struct {
			XMLName  xml.Name `xml:"doc"`
			Fields   []Field  `xml:"str"`
		} `xml:"doc"`
	} `xml:"result"`
}

type Field struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

// IPRange represents an IP range with its netname
type IPRange struct {
	Range   string
	Netname string
}

// SearchByLocation searches for IP ranges by city or country name
func SearchByLocation(location string) ([]IPRange, error) {
	// Clean and format the location query
	location = strings.TrimSpace(strings.ToLower(location))
	
	// Build RIPE DB query URL
	baseURL := "https://apps.db.ripe.net/db-web-ui/api/rest/fulltextsearch/select"
	
	// Create request URL with parameters
	params := url.Values{}
	params.Add("q", fmt.Sprintf("(\"%s\") AND (object-type:inetnum)", location))
	params.Add("facet", "true")
	params.Add("format", "xml")
	params.Add("hl", "true")
	params.Add("start", "0")
	params.Add("wt", "xml")
	
	// Create custom HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Create request
	req, err := http.NewRequest("GET", baseURL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Add headers to make it look like a browser request
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "application/xml")
	
	// Make HTTP request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query RIPE DB: %v", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RIPE DB returned status %d", resp.StatusCode)
	}

	// Check content type
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "xml") && !strings.Contains(contentType, "application/json") {
		return nil, fmt.Errorf("unexpected content type: %s", contentType)
	}
	
	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	// Check if response starts with XML declaration or response tag
	bodyStr := string(body)
	if !strings.HasPrefix(bodyStr, "<?xml") && !strings.HasPrefix(bodyStr, "<response") {
		return nil, fmt.Errorf("invalid response format: %s", bodyStr[:100])
	}
	
	// Parse XML response
	var ripeResp RIPEResponse
	if err := xml.Unmarshal(body, &ripeResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	// Validate response
	if ripeResp.Result.NumFound == 0 {
		return nil, nil // No results found
	}
	
	// Extract IP ranges with netnames
	var ranges []IPRange
	for _, doc := range ripeResp.Result.Documents {
		var inetnum, netname string
		for _, field := range doc.Fields {
			if field.Name == "inetnum" {
				inetnum = field.Value
			} else if field.Name == "netname" {
				netname = field.Value
			}
			if inetnum != "" && netname != "" {
				break
			}
		}
		if inetnum != "" {
			// Convert range format from "start - end" to CIDR
			ipRange := strings.Replace(inetnum, " ", "", -1)
			ranges = append(ranges, IPRange{Range: ipRange, Netname: netname})
		}
	}
	
	return ranges, nil
} 