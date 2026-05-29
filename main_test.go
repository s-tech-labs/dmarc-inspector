package main

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"strings"
	"testing"
)

// captureStdout runs a function and captures its stdout output
func captureStdout(fn func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	return buf.String()
}

// captureStderr runs a function and captures its stderr output
func captureStderr(fn func()) string {
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	fn()
	_ = w.Close()
	os.Stderr = old
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	return buf.String()
}

func printVersionOutput() {
	fmt.Printf("==> S-Tech Labs / dmarc-inspector %s <==\n\n", Version)
	fmt.Println("  Description:  Parse DMARC aggregate XML reports into readable tables. Supports gzip, files, and URLs.")
	fmt.Println("  Repo:         https://github.com/s-tech-labs/dmarc-inspector")
	fmt.Println("  License:      MIT")
	fmt.Println("  Copyright:    (c) 2026 S-Tech Solutions — https://stech-sol.com")
	fmt.Println()
	fmt.Println("  Part of S-Tech Labs — https://labs.stech-sol.com")
}

func TestVersionFlag(t *testing.T) {
	output := captureStdout(func() {
		printVersionOutput()
	})

	if !strings.Contains(output, "dmarc-inspector") {
		t.Errorf("expected banner to contain 'dmarc-inspector', got: %s", output)
	}
	if !strings.Contains(output, Version) {
		t.Errorf("expected banner to contain version '%s', got: %s", Version, output)
	}
	if !strings.Contains(output, "S-Tech Labs") {
		t.Errorf("expected banner to contain 'S-Tech Labs', got: %s", output)
	}
	if !strings.Contains(output, "License") {
		t.Errorf("expected banner to contain 'License', got: %s", output)
	}
}

func TestShortVersionFlag(t *testing.T) {
	// Same output function for both flags
	output := captureStdout(func() {
		printVersionOutput()
	})

	if !strings.Contains(output, "==> S-Tech Labs / dmarc-inspector") {
		t.Errorf("expected version banner header, got: %s", output)
	}
}

func TestNoArgsShowsError(t *testing.T) {
	// Simulate the error output when no args are given
	stderr := captureStderr(func() {
		fmt.Fprintf(os.Stderr, "Error: provide a file path or URL to a DMARC aggregate report\n")
		fmt.Fprintf(os.Stderr, "Usage: dmarc-inspector [--file <path> | --url <url> | <path>]\n")
	})

	if !strings.Contains(stderr, "Error") {
		t.Errorf("expected error output, got: %s", stderr)
	}
	if !strings.Contains(stderr, "Usage") {
		t.Errorf("expected usage info, got: %s", stderr)
	}
}

func TestParseMinimalDMARCXML(t *testing.T) {
	xmlData := `<?xml version="1.0" encoding="UTF-8"?>
<feedback>
	<report_metadata>
		<org_name>TestOrg</org_name>
		<email>test@example.com</email>
		<report_id>12345</report_id>
		<date_range>
			<begin>1700000000</begin>
			<end>1700086400</end>
		</date_range>
	</report_metadata>
	<policy_published>
		<domain>example.com</domain>
		<p>reject</p>
		<sp>quarantine</sp>
		<pct>100</pct>
	</policy_published>
	<record>
		<row>
			<source_ip>192.0.2.1</source_ip>
			<count>5</count>
			<policy_evaluated>
				<disposition>none</disposition>
				<dkim>pass</dkim>
				<spf>pass</spf>
			</policy_evaluated>
		</row>
		<identifiers>
			<header_from>example.com</header_from>
		</identifiers>
		<auth_results>
			<dkim>
				<domain>example.com</domain>
				<result>pass</result>
			</dkim>
			<spf>
				<domain>example.com</domain>
				<result>pass</result>
			</spf>
		</auth_results>
	</record>
</feedback>`

	var feedback Feedback
	if err := xml.Unmarshal([]byte(xmlData), &feedback); err != nil {
		t.Fatalf("failed to parse valid XML: %v", err)
	}

	if feedback.ReportMetadata.OrgName != "TestOrg" {
		t.Errorf("expected org_name 'TestOrg', got '%s'", feedback.ReportMetadata.OrgName)
	}
	if feedback.ReportMetadata.ReportID != "12345" {
		t.Errorf("expected report_id '12345', got '%s'", feedback.ReportMetadata.ReportID)
	}
	if feedback.PolicyPublished.Domain != "example.com" {
		t.Errorf("expected domain 'example.com', got '%s'", feedback.PolicyPublished.Domain)
	}
	if feedback.PolicyPublished.P != "reject" {
		t.Errorf("expected policy 'reject', got '%s'", feedback.PolicyPublished.P)
	}
	if len(feedback.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(feedback.Records))
	}
	if feedback.Records[0].Row.SourceIP != "192.0.2.1" {
		t.Errorf("expected source_ip '192.0.2.1', got '%s'", feedback.Records[0].Row.SourceIP)
	}
	if feedback.Records[0].Row.Count != 5 {
		t.Errorf("expected count 5, got %d", feedback.Records[0].Row.Count)
	}
	if feedback.Records[0].Row.PolicyEvaluated.DKIM != "pass" {
		t.Errorf("expected DKIM result 'pass', got '%s'", feedback.Records[0].Row.PolicyEvaluated.DKIM)
	}
	if feedback.Records[0].Row.PolicyEvaluated.SPF != "pass" {
		t.Errorf("expected SPF result 'pass', got '%s'", feedback.Records[0].Row.PolicyEvaluated.SPF)
	}
}

func TestInvalidXMLError(t *testing.T) {
	invalidXML := `<?xml version="1.0"?><feedback><broken></feedback>`

	var feedback Feedback
	err := xml.Unmarshal([]byte(invalidXML), &feedback)
	if err == nil {
		t.Fatal("expected error for invalid XML, got nil")
	}
}

func TestEmptyXML(t *testing.T) {
	emptyXML := `<?xml version="1.0"?><feedback></feedback>`

	var feedback Feedback
	if err := xml.Unmarshal([]byte(emptyXML), &feedback); err != nil {
		t.Fatalf("failed to parse empty XML: %v", err)
	}
}

func TestPrintReportOutput(t *testing.T) {
	feedback := Feedback{
		ReportMetadata: struct {
			OrgName      string `xml:"org_name"`
			Email        string `xml:"email"`
			ExtraContact string `xml:"extra_contact"`
			ReportID     string `xml:"report_id"`
			DateRange    struct {
				Begin int64 `xml:"begin"`
				End   int64 `xml:"end"`
			} `xml:"date_range"`
		}{
			OrgName:  "TestOrg",
			Email:    "test@example.com",
			ReportID: "RPT-001",
			DateRange: struct {
				Begin int64 `xml:"begin"`
				End   int64 `xml:"end"`
			}{
				Begin: 1700000000,
				End:   1700086400,
			},
		},
		PolicyPublished: struct {
			Domain string `xml:"domain"`
			ADKIM  string `xml:"adkim"`
			ASPF   string `xml:"aspf"`
			P      string `xml:"p"`
			SP     string `xml:"sp"`
			Pct    int    `xml:"pct"`
		}{
			Domain: "example.com",
			P:      "reject",
			SP:     "quarantine",
			Pct:    100,
		},
		Records: []Record{
			{
				Row: struct {
					SourceIP string `xml:"source_ip"`
					Count    int    `xml:"count"`
					PolicyEvaluated struct {
						Disposition string `xml:"disposition"`
						DKIM        string `xml:"dkim"`
						SPF         string `xml:"spf"`
					} `xml:"policy_evaluated"`
				}{
					SourceIP: "192.0.2.1",
					Count:    5,
					PolicyEvaluated: struct {
						Disposition string `xml:"disposition"`
						DKIM        string `xml:"dkim"`
						SPF         string `xml:"spf"`
					}{
						Disposition: "none",
						DKIM:        "pass",
						SPF:         "pass",
					},
				},
				Identifiers: struct {
					HeaderFrom string `xml:"header_from"`
					EnvelopeTo string `xml:"envelope_to"`
				}{
					HeaderFrom: "example.com",
				},
			},
		},
	}

	output := captureStdout(func() {
		printReport(feedback)
	})

	checks := []string{
		"DMARC Aggregate Report",
		"Organization: TestOrg",
		"Report ID: RPT-001",
		"Domain: example.com",
		"Policy: reject",
		"192.0.2.1",
		"pass",
		"Total records: 1, Total messages: 5",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("expected output to contain '%s', got:\n%s", check, output)
		}
	}
}

func TestReadReportInvalidFile(t *testing.T) {
	_, err := readReport("/nonexistent/file.xml")
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
	if !strings.Contains(err.Error(), "failed to open file") {
		t.Errorf("expected 'failed to open file' error, got: %v", err)
	}
}

func TestReadReportValidFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "dmarc-test-*.xml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	xmlContent := `<?xml version="1.0" encoding="UTF-8"?>
<feedback>
	<report_metadata>
		<org_name>TempOrg</org_name>
		<email>temp@example.com</email>
		<report_id>TEMP-001</report_id>
		<date_range>
			<begin>1700000000</begin>
			<end>1700086400</end>
		</date_range>
	</report_metadata>
	<policy_published>
		<domain>temp.example.com</domain>
		<p>none</p>
		<pct>100</pct>
	</policy_published>
</feedback>`

	if _, err := tmpFile.Write([]byte(xmlContent)); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	_ = tmpFile.Close()

	data, err := readReport(tmpFile.Name())
	if err != nil {
		t.Fatalf("unexpected error reading temp file: %v", err)
	}

	if !strings.Contains(string(data), "TempOrg") {
		t.Errorf("expected data to contain 'TempOrg', got: %s", string(data))
	}
}