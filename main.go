package main

import (
	"compress/gzip"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

var Version = "v0.1.0"

// DMARC XML structures
type Feedback struct {
	XMLName        xml.Name `xml:"feedback"`
	ReportMetadata struct {
		OrgName      string `xml:"org_name"`
		Email        string `xml:"email"`
		ExtraContact string `xml:"extra_contact"`
		ReportID     string `xml:"report_id"`
		DateRange    struct {
			Begin int64 `xml:"begin"`
			End   int64 `xml:"end"`
		} `xml:"date_range"`
	} `xml:"report_metadata"`
	PolicyPublished struct {
		Domain string `xml:"domain"`
		ADKIM  string `xml:"adkim"`
		ASPF   string `xml:"aspf"`
		P      string `xml:"p"`
		SP     string `xml:"sp"`
		Pct    int    `xml:"pct"`
	} `xml:"policy_published"`
	Records []Record `xml:"record"`
}

type Record struct {
	Row struct {
		SourceIP string `xml:"source_ip"`
		Count    int    `xml:"count"`
		PolicyEvaluated struct {
			Disposition string `xml:"disposition"`
			DKIM        string `xml:"dkim"`
			SPF         string `xml:"spf"`
		} `xml:"policy_evaluated"`
	} `xml:"row"`
	Identifiers struct {
		HeaderFrom string `xml:"header_from"`
		EnvelopeTo string `xml:"envelope_to"`
	} `xml:"identifiers"`
	AuthResults struct {
		DKIM []struct {
			Domain string `xml:"domain"`
			Result string `xml:"result"`
		} `xml:"dkim"`
		SPF []struct {
			Domain string `xml:"domain"`
			Result string `xml:"result"`
		} `xml:"spf"`
	} `xml:"auth_results"`
}

func main() {
	var showVersion bool
	flag.BoolVar(&showVersion, "version", false, "Show version")
	flag.BoolVar(&showVersion, "V", false, "Show version (shorthand)")
	var filePath string
	flag.StringVar(&filePath, "file", "", "Path to DMARC aggregate report XML file (may be gzipped)")
	flag.StringVar(&filePath, "f", "", "Path to DMARC aggregate report XML file (shorthand)")
	urlStr := flag.String("url", "", "URL to DMARC aggregate report XML file")
	flag.Parse()

	if showVersion {
		fmt.Printf("==> S-Tech Labs / dmarc-inspector %s <==\n\n", Version)
		fmt.Println("  Description:  Parse DMARC aggregate XML reports into readable tables. Supports gzip, files, and URLs.")
		fmt.Println("  Repo:         https://github.com/s-tech-labs/dmarc-inspector")
		fmt.Println("  License:      MIT")
		fmt.Println("  Copyright:    (c) 2026 S-Tech Solutions — https://stech-sol.com")
		fmt.Println()
		fmt.Println("  Part of S-Tech Labs — https://labs.stech-sol.com")
		os.Exit(0)
	}

	var source string
	if filePath != "" {
		source = filePath
	} else if *urlStr != "" {
		source = *urlStr
	} else if flag.NArg() > 0 {
		source = flag.Arg(0)
	} else {
		fmt.Fprintf(os.Stderr, "Error: provide a file path or URL to a DMARC aggregate report\n")
		fmt.Fprintf(os.Stderr, "Usage: dmarc-inspector [--file <path> | --url <url> | <path>]\n")
		os.Exit(1)
	}

	data, err := readReport(source)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading report: %v\n", err)
		os.Exit(1)
	}

	var feedback Feedback
	if err := xml.Unmarshal(data, &feedback); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing XML: %v\n", err)
		os.Exit(1)
	}

	printReport(feedback)
}

func readReport(source string) ([]byte, error) {
	var reader io.ReadCloser

	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Get(source)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch URL: %w", err)
		}
		defer resp.Body.Close()
		reader = resp.Body
	} else {
		f, err := os.Open(source)
		if err != nil {
			return nil, fmt.Errorf("failed to open file: %w", err)
		}
		defer f.Close()
		reader = f
	}

	// Try gzip first, fallback to raw
	gzReader, err := gzip.NewReader(reader)
	if err != nil {
		// Not gzip compressed, read raw
		if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
			// Reset reader for URL case - need to re-fetch
			client := &http.Client{Timeout: 30 * time.Second}
			resp, err := client.Get(source)
			if err != nil {
				return nil, fmt.Errorf("failed to fetch URL: %w", err)
			}
			defer resp.Body.Close()
			return io.ReadAll(resp.Body)
		}
		f, err := os.Open(source)
		if err != nil {
			return nil, fmt.Errorf("failed to open file: %w", err)
		}
		defer f.Close()
		return io.ReadAll(f)
	}
	defer gzReader.Close()
	return io.ReadAll(gzReader)
}

func printReport(f Feedback) {
	begin := time.Unix(f.ReportMetadata.DateRange.Begin, 0)
	end := time.Unix(f.ReportMetadata.DateRange.End, 0)

	fmt.Printf("DMARC Aggregate Report\n")
	fmt.Printf("Organization: %s\n", f.ReportMetadata.OrgName)
	fmt.Printf("Report ID: %s\n", f.ReportMetadata.ReportID)
	fmt.Printf("Domain: %s\n", f.PolicyPublished.Domain)
	fmt.Printf("Policy: %s (subdomain: %s, pct: %d%%)\n", f.PolicyPublished.P, f.PolicyPublished.SP, f.PolicyPublished.Pct)
	fmt.Printf("Period: %s - %s\n", begin.Format("2006-01-02 15:04:05"), end.Format("2006-01-02 15:04:05"))
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "Domain\tDKIM Result\tSPF Result\tDisposition\tSource IP\tCount\n")
	fmt.Fprintf(w, "------\t-----------\t----------\t-----------\t---------\t-----\n")

	for _, rec := range f.Records {
		domain := rec.Identifiers.HeaderFrom
		dkimResult := rec.Row.PolicyEvaluated.DKIM
		spfResult := rec.Row.PolicyEvaluated.SPF
		disposition := rec.Row.PolicyEvaluated.Disposition
		sourceIP := rec.Row.SourceIP
		count := rec.Row.Count

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\n", domain, dkimResult, spfResult, disposition, sourceIP, count)
	}
	w.Flush()

	// Summary
	var total int
	for _, rec := range f.Records {
		total += rec.Row.Count
	}
	fmt.Printf("\nTotal records: %d, Total messages: %d\n", len(f.Records), total)
}