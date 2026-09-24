package main

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// -write replaces what the run attempted and keeps the rest. ML-DSA-44 is no
// longer benchmarked here (it moved into tdns); its last measurement must
// survive the next run on the same architecture.
func TestWriteCostsFileKeepsRowsItDidNotAttempt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "algorithm-costs.yaml")
	existing := `costs:
    amd64:
        MLDSA44: { signing: 2.8, validation: 1.7 }
        FALCON512: { signing: 9, validation: 2 }
        MAYO1: { signing: 4, validation: 3 }
    arm64:
        MLDSA44: { signing: 3.1, validation: 1.9 }
`
	if err := os.WriteFile(path, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}
	results := []result{
		{name: referenceName, signNs: 100, verifyNs: 100},
		{name: "FALCON512", signNs: 500, verifyNs: 200},
		{name: "MAYO1", skipped: "liboqs not available"},
	}
	if err := writeCostsFile(path, "amd64", results, 100, 100); err != nil {
		t.Fatalf("writeCostsFile: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cf costsFile
	if err := yaml.Unmarshal(data, &cf); err != nil {
		t.Fatalf("written file does not parse: %v\n%s", err, data)
	}
	amd := cf.Costs["amd64"]
	if got := amd["MLDSA44"]; got != (cost{Signing: 2.8, Validation: 1.7}) {
		t.Errorf("MLDSA44 (not attempted) = %+v, want its last measurement kept", got)
	}
	if got := amd["FALCON512"]; got != (cost{Signing: 5, Validation: 2}) {
		t.Errorf("FALCON512 (measured) = %+v, want the new measurement", got)
	}
	if _, ok := amd["MAYO1"]; ok {
		t.Error("MAYO1 (attempted, skipped) was kept; a skipped algorithm is dropped, as before")
	}
	if got := amd[referenceName]; got != (cost{Signing: 1, Validation: 1}) {
		t.Errorf("%s = %+v, want 1/1", referenceName, got)
	}
	if got := cf.Costs["arm64"]["MLDSA44"]; got != (cost{Signing: 3.1, Validation: 1.9}) {
		t.Errorf("arm64 block changed: MLDSA44 = %+v", got)
	}
}
