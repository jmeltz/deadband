package inventory

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Device struct {
	IP       string `json:"ip"`
	Vendor   string `json:"vendor"`
	Model    string `json:"model"`
	Firmware string `json:"firmware"`
}

func ParseFile(path string, format string) ([]Device, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening inventory: %w", err)
	}
	defer f.Close()

	if format == "" || format == "auto" {
		format = detectFormat(path, f)
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return nil, fmt.Errorf("seeking inventory file: %w", err)
		}
	}

	switch format {
	case "csv":
		return parseCSV(f)
	case "json":
		return parseJSON(f)
	case "flat":
		return parseFlat(f)
	default:
		return nil, fmt.Errorf("unsupported inventory format: %s", format)
	}
}

func detectFormat(path string, f *os.File) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return "json"
	case ".csv":
		return "csv"
	case ".txt", ".flat":
		return "flat"
	}
	buf := make([]byte, 64)
	n, _ := f.Read(buf)
	content := strings.TrimSpace(string(buf[:n]))
	if strings.HasPrefix(content, "[") || strings.HasPrefix(content, "{") {
		return "json"
	}
	return "csv"
}

func parseCSV(r io.Reader) ([]Device, error) {
	reader := csv.NewReader(r)
	headers, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("reading CSV headers: %w", err)
	}

	colIndex := make(map[string]int)
	for i, h := range headers {
		colIndex[strings.TrimSpace(h)] = i
	}

	isRockwellSchema := false
	if _, ok := colIndex["Device Name"]; ok {
		if _, ok := colIndex["Product Revision"]; ok {
			isRockwellSchema = true
		}
	}

	var devices []Device
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading CSV row: %w", err)
		}

		var dev Device
		if isRockwellSchema {
			dev.Vendor = "Rockwell Automation"
			if i, ok := colIndex["IP Address"]; ok && i < len(record) {
				dev.IP = strings.TrimSpace(record[i])
			} else if i, ok := colIndex["Scanned IP"]; ok && i < len(record) {
				dev.IP = strings.TrimSpace(record[i])
			}
			if i, ok := colIndex["Device Name"]; ok && i < len(record) {
				dev.Model = strings.TrimSpace(record[i])
			}
			if i, ok := colIndex["Product Revision"]; ok && i < len(record) {
				dev.Firmware = strings.TrimSpace(record[i])
			}
		} else {
			// Generic CSV: IP, Vendor, Model, Firmware
			if len(record) >= 4 {
				dev.IP = strings.TrimSpace(record[0])
				dev.Vendor = strings.TrimSpace(record[1])
				dev.Model = strings.TrimSpace(record[2])
				dev.Firmware = strings.TrimSpace(record[3])
			}
		}

		if dev.IP != "" && dev.Model != "" {
			devices = append(devices, dev)
		}
	}
	return devices, nil
}

type rockwellJSONDevice struct {
	ScannedIP       string `json:"scanned_ip"`
	DeviceName      string `json:"device_name"`
	MAC             string `json:"mac"`
	IP              string `json:"ip"`
	ProductRevision string `json:"product_revision"`
	Serial          string `json:"serial"`
	Status          string `json:"status"`
	Uptime          string `json:"uptime"`
}

func parseJSON(r io.Reader) ([]Device, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading JSON: %w", err)
	}

	var rockwell []rockwellJSONDevice
	if err := json.Unmarshal(data, &rockwell); err == nil && len(rockwell) > 0 && rockwell[0].DeviceName != "" {
		devices := make([]Device, 0, len(rockwell))
		for _, r := range rockwell {
			ip := r.IP
			if ip == "" {
				ip = r.ScannedIP
			}
			devices = append(devices, Device{
				IP:       ip,
				Vendor:   "Rockwell Automation",
				Model:    r.DeviceName,
				Firmware: r.ProductRevision,
			})
		}
		return devices, nil
	}

	// Generic JSON array: [{ip, vendor, model, firmware}]
	var generic []struct {
		IP       string `json:"ip"`
		Vendor   string `json:"vendor"`
		Model    string `json:"model"`
		Firmware string `json:"firmware"`
	}
	if err := json.Unmarshal(data, &generic); err != nil {
		return nil, fmt.Errorf("parsing JSON inventory: %w", err)
	}
	devices := make([]Device, 0, len(generic))
	for _, g := range generic {
		if g.IP != "" && g.Model != "" {
			devices = append(devices, Device{
				IP:       g.IP,
				Vendor:   g.Vendor,
				Model:    g.Model,
				Firmware: g.Firmware,
			})
		}
	}
	return devices, nil
}

func parseFlat(r io.Reader) ([]Device, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading flat inventory: %w", err)
	}

	var devices []Device
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ",", 4)
		if len(parts) < 4 {
			continue
		}
		devices = append(devices, Device{
			IP:       strings.TrimSpace(parts[0]),
			Vendor:   strings.TrimSpace(parts[1]),
			Model:    strings.TrimSpace(parts[2]),
			Firmware: strings.TrimSpace(parts[3]),
		})
	}
	return devices, nil
}
