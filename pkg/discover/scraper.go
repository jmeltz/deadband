package discover

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/net/html"
)

var deviceFields = []string{
	"Device Name",
	"Device Description",
	"Device Location",
	"Ethernet Address (MAC)",
	"IP Address",
	"Product Revision",
	"Firmware Version Date",
	"Serial Number",
	"Status",
	"Uptime",
}

func ScrapeDevice(client *http.Client, ip string) (map[string]string, error) {
	url := fmt.Sprintf("http://%s/home.asp", ip)

	ctx, cancel := context.WithTimeout(context.Background(), client.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return parseHomeASP(resp.Body)
}

func parseHomeASP(r io.Reader) (map[string]string, error) {
	doc, err := html.Parse(r)
	if err != nil {
		return nil, err
	}

	info := make(map[string]string)
	fieldSet := make(map[string]bool)
	for _, f := range deviceFields {
		fieldSet[f] = true
	}

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "tr" {
			tds := collectTDs(n)
			if len(tds) == 2 {
				label := strings.TrimSpace(textContent(tds[0]))
				value := strings.TrimSpace(textContent(tds[1]))
				if fieldSet[label] {
					info[label] = value
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	return info, nil
}

func collectTDs(tr *html.Node) []*html.Node {
	var tds []*html.Node
	for c := tr.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && c.Data == "td" {
			tds = append(tds, c)
		}
	}
	return tds
}

func textContent(n *html.Node) string {
	if n.Type == html.TextNode {
		return n.Data
	}
	var sb strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		sb.WriteString(textContent(c))
	}
	return sb.String()
}
