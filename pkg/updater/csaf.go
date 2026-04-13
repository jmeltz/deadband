package updater

import "encoding/json"

type csafDoc struct {
	Document        csafDocument        `json:"document"`
	ProductTree     csafProductTree     `json:"product_tree"`
	Vulnerabilities []csafVulnerability `json:"vulnerabilities"`
}

type csafDocument struct {
	Title      string          `json:"title"`
	Tracking   csafTracking    `json:"tracking"`
	References []csafReference `json:"references"`
	Notes      []csafNote      `json:"notes,omitempty"`
}

type csafNote struct {
	Category string `json:"category"`
	Title    string `json:"title,omitempty"`
	Text     string `json:"text"`
}

type csafTracking struct {
	ID                 string `json:"id"`
	CurrentReleaseDate string `json:"current_release_date"`
	InitialReleaseDate string `json:"initial_release_date"`
}

type csafReference struct {
	URL      string `json:"url"`
	Category string `json:"category"`
}

type csafProductTree struct {
	Branches []csafBranch `json:"branches"`
}

type csafBranch struct {
	Category string        `json:"category"`
	Name     string        `json:"name"`
	Branches []csafBranch  `json:"branches"`
	Product  *csafProduct  `json:"product,omitempty"`
}

type csafProduct struct {
	Name      string              `json:"name"`
	ProductID string              `json:"product_id"`
	Helpers   *csafProductHelpers `json:"product_identification_helper,omitempty"`
}

type csafProductHelpers struct {
	CPE string `json:"cpe,omitempty"`
}

type csafVulnerability struct {
	CVE           string              `json:"cve"`
	Scores        []csafScore         `json:"scores"`
	ProductStatus *csafProductStatus  `json:"product_status,omitempty"`
	CWE           *csafCWE            `json:"cwe,omitempty"`
	Notes         []csafNote          `json:"notes,omitempty"`
	Remediations  []csafRemediation   `json:"remediations,omitempty"`
}

type csafCWE struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type csafRemediation struct {
	Category string `json:"category"`
	Details  string `json:"details"`
	URL      string `json:"url,omitempty"`
}

type csafScore struct {
	CVSSv3   json.RawMessage `json:"cvss_v3,omitempty"`
	Products []string        `json:"products,omitempty"`
}

type csafCVSS struct {
	BaseScore float64 `json:"baseScore"`
}

type csafProductStatus struct {
	KnownAffected    []string `json:"known_affected,omitempty"`
	KnownNotAffected []string `json:"known_not_affected,omitempty"`
	Fixed            []string `json:"fixed,omitempty"`
}

type productInfo struct {
	Name    string
	Version string
}

func extractFromTree(branches []csafBranch) (vendor string, products []string, versions []string, productIDs map[string]productInfo) {
	productIDs = make(map[string]productInfo)
	walkBranches(branches, "", "", productIDs, &vendor, &products, &versions)
	return
}

func walkBranches(branches []csafBranch, currentVendor, currentProduct string, productIDs map[string]productInfo, vendor *string, products *[]string, versions *[]string) {
	for _, b := range branches {
		v := currentVendor
		p := currentProduct

		switch b.Category {
		case "vendor":
			v = b.Name
			if *vendor == "" {
				*vendor = b.Name
			}
		case "product_name":
			p = b.Name
			*products = append(*products, b.Name)
		case "product_version", "product_version_range":
			*versions = append(*versions, b.Name)
		}

		if b.Product != nil && b.Product.ProductID != "" {
			productIDs[b.Product.ProductID] = productInfo{
				Name:    p,
				Version: b.Name,
			}
		}

		if len(b.Branches) > 0 {
			walkBranches(b.Branches, v, p, productIDs, vendor, products, versions)
		}
	}
}
