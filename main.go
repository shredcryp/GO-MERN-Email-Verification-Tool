package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
)

type DomainVerificationResult struct {
	Domain       string `json:"domain"`
	HasMX        bool   `json:"hasMX"`
	HasSPF       bool   `json:"hasSPF"`
	SPFRecord    string `json:"spfRecord"`
	HasDMARC     bool   `json:"hasDMARC"`
	DMARCRecord  string `json:"dmarcRecord"`
	ErrorMessage string `json:"errorMessage,omitempty"`
}

func main() {
	http.HandleFunc("/verify-domain", handleDomainVerification)
	port := "8080"
	fmt.Printf("Server is listening on port %s...\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func handleDomainVerification(w http.ResponseWriter, r *http.Request) {
	setupCors(&w, r)
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	domain := strings.TrimSpace(r.FormValue("domain"))
	if domain == "" {
		http.Error(w, "Domain is required", http.StatusBadRequest)
		return
	}

	result := DomainVerificationResult{
		Domain: domain,
	}

	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Error looking up MX records: %v", err)
		respondJSON(w, http.StatusOK, result)
		return
	}

	result.HasMX = len(mxRecords) > 0
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Error looking up TXT records: %v", err)
		respondJSON(w, http.StatusOK, result)
		return
	}

	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=spf1") {
			result.HasSPF = true
			result.SPFRecord = record
			break
		}
	}

	dmarcRecords, err := net.LookupTXT("_dmarc." + domain)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Error looking up DMARC records: %v", err)
		respondJSON(w, http.StatusOK, result)
		return
	}

	for _, record := range dmarcRecords {
		if strings.HasPrefix(record, "v=DMARC1") {
			result.HasDMARC = true
			result.DMARCRecord = record
			break
		}
	}

	respondJSON(w, http.StatusOK, result)
}

func setupCors(w *http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin != "" {
		(*w).Header().Set("Access-Control-Allow-Origin", origin)
	}

	(*w).Header().Set("Access-Control-Allow-Methods", "POST")
	(*w).Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

func respondJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	encoder := json.NewEncoder(w)
	encoder.Encode(data)
}
