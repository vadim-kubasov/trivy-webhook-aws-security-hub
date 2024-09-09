package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	Trivytypes "github.com/csepulveda/trivy-webhook-aws-security-hub/types"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/gorilla/mux"
)

// ProcessTrivyWebhook processes incoming vulnerability reports
func ProcessTrivyWebhook(w http.ResponseWriter, r *http.Request) {
	var report Trivytypes.VulnerabilityReport

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		log.Printf("Error reading request body: %v", err)
		return
	}

	// Validate request body is not empty
	if len(body) == 0 {
		http.Error(w, "Empty request body", http.StatusBadRequest)
		log.Printf("Empty request body")
		return
	}

	// Decode JSON
	err = json.Unmarshal(body, &report)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		log.Printf("Error decoding JSON: %v", err)
		return
	}

	//Continue only if report.Kind is a VulnerabilityReport
	if report.Kind != "VulnerabilityReport" {
		http.Error(w, "Invalid report kind", http.StatusBadRequest)
		log.Printf("Invalid report kind: %s", report.Kind)
		return
	}

	//Continue only if report.Report.Vulnerabilities exists
	if len(report.Report.Vulnerabilities) == 0 {
		http.Error(w, "No vulnerabilities found", http.StatusBadRequest)
		log.Printf("No vulnerabilities found in the report")
		return
	}

	// Import findings to AWS Security Hub
	err = importFindingsToSecurityHub(report)
	if err != nil {
		http.Error(w, "Error importing findings to Security Hub", http.StatusInternalServerError)
		log.Printf("Error importing findings to Security Hub: %v", err)
		return
	}

	// Return a success response
	w.WriteHeader(http.StatusOK)
	_, err = w.Write([]byte("Vulnerabilities processed and imported to Security Hub"))
	if err != nil {
		log.Printf("Error writing response: %v", err)
	}

}

// importFindingsToSecurityHub imports vulnerabilities to AWS Security Hub
func importFindingsToSecurityHub(report Trivytypes.VulnerabilityReport) error {
	log.Printf("Processing report: %s", report.Metadata.Name)

	// Load AWS SDK config
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return fmt.Errorf("unable to load SDK config: %v", err)
	}

	// Create AWS Security Hub and STS clients
	client := securityhub.NewFromConfig(cfg)
	stsClient := sts.NewFromConfig(cfg)
	callerIdentity, err := stsClient.GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("failed to get caller identity: %w", err)
	}

	// Prepare variables
	AWSAccountID := aws.ToString(callerIdentity.Account)
	AWSRegion := cfg.Region
	ProductArn := fmt.Sprintf("arn:aws:securityhub:%s::product/aquasecurity/aquasecurity", AWSRegion)
	Container := report.Metadata.Labels["trivy-operator.container.name"]
	Registry := report.Report.Registry.Server
	Repository := report.Report.Artifact.Repository
	Digest := report.Report.Artifact.Digest
	FullImageName := fmt.Sprintf("%s/%s:%s", Registry, Repository, Digest)
	ImageName := fmt.Sprintf("%s/%s", Registry, Repository)

	// Prepare findings for AWS Security Hub BatchImportFindings API
	var findings []types.AwsSecurityFinding

	// Handle Vulnerabilities
	for _, vuln := range report.Report.Vulnerabilities {
		severity := vuln.Severity
		if severity == "UNKNOWN" {
			severity = "INFORMATIONAL"
		}

		// Truncate description if too long
		description := vuln.Title
		if len(description) > 512 {
			description = description[:512] + "..."
		}

		findings = append(findings, types.AwsSecurityFinding{
			SchemaVersion: aws.String("2018-10-08"),
			Id:            aws.String(fmt.Sprintf("%s-%s", FullImageName, vuln.VulnerabilityID)),
			ProductArn:    aws.String(ProductArn),
			GeneratorId:   aws.String(fmt.Sprintf("Trivy/%s", vuln.VulnerabilityID)),
			AwsAccountId:  aws.String(AWSAccountID),
			Types:         []string{"Software and Configuration Checks/Vulnerabilities/CVE"},
			CreatedAt:     aws.String(time.Now().Format(time.RFC3339)),
			UpdatedAt:     aws.String(time.Now().Format(time.RFC3339)),
			Severity:      &types.Severity{Label: types.SeverityLabel(severity)},
			Title:         aws.String(fmt.Sprintf("Trivy found a vulnerability in %s/%s related to %s", ImageName, Container, vuln.VulnerabilityID)),
			Description:   aws.String(description),
			Remediation: &types.Remediation{
				Recommendation: &types.Recommendation{
					Text: aws.String("Upgrade to version " + vuln.FixedVersion),
					Url:  aws.String(vuln.PrimaryLink),
				},
			},
			ProductFields: map[string]string{"Product Name": "Trivy"},
			Resources: []types.Resource{
				{
					Type:      aws.String("Container"),
					Id:        aws.String(ImageName),
					Partition: types.PartitionAws,
					Region:    aws.String(AWSRegion),
					Details: &types.ResourceDetails{
						Other: map[string]string{
							"Container Image":   ImageName,
							"CVE ID":            vuln.VulnerabilityID,
							"CVE Title":         vuln.Title,
							"PkgName":           vuln.Resource,
							"Installed Package": vuln.InstalledVersion,
							"Patched Package":   vuln.FixedVersion,
							"NvdCvssScoreV3":    fmt.Sprintf("%f", vuln.Score),
							"NvdCvssVectorV3":   "",
						},
					},
				},
			},
			RecordState: types.RecordStateActive,
		})
	}

	// // Handle Misconfigurations (if present)
	// for _, misconfig := range report.Report.Misconfigurations {
	// TODO: Implement handling of Misconfigurations
	// }

	// Handle Secrets (if present)
	// for _, secret := range report.Report.Secrets {
	// TODO: Implement handling of Secrets
	// }

	// Import findings to AWS Security Hub in batches of 100
	batchSize := 100
	for i := 0; i < len(findings); i += batchSize {
		end := i + batchSize
		if end > len(findings) {
			end = len(findings)
		}

		batch := findings[i:end]

		input := &securityhub.BatchImportFindingsInput{
			Findings: batch,
		}

		// Call BatchImportFindings API
		_, err := client.BatchImportFindings(context.TODO(), input)
		if err != nil {
			return fmt.Errorf("error importing findings to Security Hub: %v", err)
		}
	}

	log.Printf("%d Findings imported to Security Hub", len(findings))
	return nil
}

func main() {
	r := mux.NewRouter()

	// Define route
	r.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("OK"))
		if err != nil {
			log.Printf("Error writing response: %v", err)
		}

	}).Methods("GET")

	r.HandleFunc("/trivy-webhook", ProcessTrivyWebhook).Methods("POST")

	// Start the server
	port := ":8080"
	fmt.Println("Starting server on port", port)
	log.Fatal(http.ListenAndServe(port, r))
}
