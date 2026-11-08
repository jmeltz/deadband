package asset

// FieldObservation retains device claims separately from the current inventory.
// Query records hold the complete response and execution metrics.
type FieldObservation struct {
	PlanID      string `json:"plan_id"`
	PlanHash    string `json:"plan_hash"`
	Field       string `json:"field"`
	Value       string `json:"value"`
	RawValue    string `json:"raw_value,omitempty"`
	Protocol    string `json:"protocol"`
	Operation   string `json:"operation"`
	Component   string `json:"component"`
	VersionKind string `json:"version_kind,omitempty"`
	ObservedAt  string `json:"observed_at"`
	Conflict    bool   `json:"conflict"`
}
