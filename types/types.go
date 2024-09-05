package Trivytypes

import "time"

// VulnerabilityReport represents the main structure of the report
type VulnerabilityReport struct {
	Kind       string   `json:"kind"`
	APIVersion string   `json:"apiVersion"`
	Metadata   Metadata `json:"metadata"`
	Report     Report   `json:"report"`
}

// Metadata contains the metadata information of the report
type Metadata struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace"`
	UID               string            `json:"uid"`
	ResourceVersion   string            `json:"resourceVersion"`
	Generation        int               `json:"generation"`
	CreationTimestamp time.Time         `json:"creationTimestamp"`
	Labels            map[string]string `json:"labels"`
	Annotations       map[string]string `json:"annotations"`
	OwnerReferences   []OwnerReference  `json:"ownerReferences"`
	ManagedFields     []ManagedField    `json:"managedFields"`
}

// OwnerReference contains details about the resource's owner
type OwnerReference struct {
	APIVersion         string `json:"apiVersion"`
	Kind               string `json:"kind"`
	Name               string `json:"name"`
	UID                string `json:"uid"`
	Controller         bool   `json:"controller"`
	BlockOwnerDeletion bool   `json:"blockOwnerDeletion"`
}

// ManagedField contains information about managed fields
type ManagedField struct {
	Manager    string    `json:"manager"`
	Operation  string    `json:"operation"`
	APIVersion string    `json:"apiVersion"`
	Time       time.Time `json:"time"`
	FieldsType string    `json:"fieldsType"`
}

// ReportFields contains fields related to the report itself
type ReportFields struct {
	Artifact        ArtifactFields `json:"f:artifact"`
	OS              OSFields       `json:"f:os"`
	Registry        RegistryFields `json:"f:registry"`
	Scanner         ScannerFields  `json:"f:scanner"`
	Summary         SummaryFields  `json:"f:summary"`
	UpdateTimestamp interface{}    `json:"f:updateTimestamp"`
	Vulnerabilities interface{}    `json:"f:vulnerabilities"`
}

// Report represents the report's detailed information
type Report struct {
	UpdateTimestamp time.Time       `json:"updateTimestamp"`
	Scanner         Scanner         `json:"scanner"`
	Registry        Registry        `json:"registry"`
	Artifact        Artifact        `json:"artifact"`
	OS              OS              `json:"os"`
	Summary         Summary         `json:"summary"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Scanner represents the scanner details
type Scanner struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}

// Registry represents the container registry information
type Registry struct {
	Server string `json:"server"`
}

// Artifact contains the artifact details of the scan
type Artifact struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
}

// OS contains the operating system details
type OS struct {
	Family string `json:"family"`
	Name   string `json:"name"`
}

// Summary represents the vulnerability count summary
type Summary struct {
	CriticalCount int `json:"criticalCount"`
	HighCount     int `json:"highCount"`
	MediumCount   int `json:"mediumCount"`
	LowCount      int `json:"lowCount"`
	UnknownCount  int `json:"unknownCount"`
	NoneCount     int `json:"noneCount"`
}

// Vulnerability represents each vulnerability found in the scan
type Vulnerability struct {
	VulnerabilityID  string    `json:"vulnerabilityID"`
	Resource         string    `json:"resource"`
	InstalledVersion string    `json:"installedVersion"`
	FixedVersion     string    `json:"fixedVersion"`
	PublishedDate    time.Time `json:"publishedDate"`
	LastModifiedDate time.Time `json:"lastModifiedDate"`
	Severity         string    `json:"severity"`
	Title            string    `json:"title"`
	PrimaryLink      string    `json:"primaryLink"`
	Links            []string  `json:"links"`
	Score            float64   `json:"score"`
	Target           string    `json:"target"`
}

// ArtifactFields, OSFields, RegistryFields, ScannerFields, SummaryFields represent nested fields for each part of the report
type ArtifactFields struct {
	Digest     interface{} `json:"f:digest"`
	Repository interface{} `json:"f:repository"`
}

type OSFields struct {
	Family interface{} `json:"f:family"`
	Name   interface{} `json:"f:name"`
}

type RegistryFields struct {
	Server interface{} `json:"f:server"`
}

type ScannerFields struct {
	Name    interface{} `json:"f:name"`
	Vendor  interface{} `json:"f:vendor"`
	Version interface{} `json:"f:version"`
}

type SummaryFields struct {
	CriticalCount interface{} `json:"f:criticalCount"`
	HighCount     interface{} `json:"f:highCount"`
	MediumCount   interface{} `json:"f:mediumCount"`
	LowCount      interface{} `json:"f:lowCount"`
	NoneCount     interface{} `json:"f:noneCount"`
	UnknownCount  interface{} `json:"f:unknownCount"`
}
