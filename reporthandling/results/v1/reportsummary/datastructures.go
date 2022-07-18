package reportsummary

import (
	"github.com/armosec/opa-utils/reporthandling/apis"
	helpersv1 "github.com/armosec/opa-utils/reporthandling/helpers/v1"
)

type PostureAttributes struct {
	Attribute string   `json:"attributeName"`
	Values    []string `json:"values"`
}

type ControlSummaries map[string]ControlSummary

// SummaryDetails detailed summary of the scanning. will contain versions, counters, etc.
type SummaryDetails struct {
	Score                 float32                      `json:"score"`                           // overall score
	Status                apis.ScanningStatus          `json:"status"`                          // overall status
	Frameworks            []FrameworkSummary           `json:"frameworks"`                      // list of framework summary
	FrameworksSubsections []FrameworkSubsectionSummary `json:"frameworksSubsections,omitempty"` // list of framework subsections summary
	Controls              ControlSummaries             `json:"controls,omitempty"`              // mapping of control - map[<control ID>]<control summary>
	ResourceCounters      ResourceCounters             `json:",inline"`
}

// FrameworkSummary summary of scanning from a single framework perspective
type FrameworkSummary struct {
	Name             string              `json:"name"` // framework name
	Status           apis.ScanningStatus `json:"status"`
	Score            float32             `json:"score"`              // framework score
	Version          string              `json:"version"`            // framework version
	Controls         ControlSummaries    `json:"controls,omitempty"` // mapping of control - map[<control ID>]<control summary>
	ResourceCounters ResourceCounters    `json:",inline"`
}

// FrameworkSummary summary of scanning from a single framework perspective
type FrameworkSubsectionSummary struct {
	Name          string                       `json:"name"`         // subsection name
	Framework     string                       `json:"framework"`    // framework name
	ID            string                       `json:"id"`           // subsection id
	ControlsStats map[apis.ScanningStatus]uint `json:"controlStats"` // control statistics
	// Score            float32             `json:"score"`        		// subsection score
	// Status           apis.ScanningStatus `json:"status"`       		// subsection status
	// Controls         ControlSummaries    `json:"controls,omitempty"` // mapping of control - map[<control ID>]<control summary>
	// ResourceCounters ResourceCounters    `json:",inline"`
}

// ControlSummary summary of scanning from a single control perspective
type ControlSummary struct {
	ControlID        string              `json:"controlID"`
	Name             string              `json:"name"`
	Status           apis.ScanningStatus `json:"status"`
	StatusInfo       apis.StatusInfo     `json:"statusInfo,omitempty"`
	Score            float32             `json:"score"`
	ScoreFactor      float32             `json:"scoreFactor"`
	ResourceIDs      helpersv1.AllLists  `json:"resourceIDs"`
	ResourceCounters ResourceCounters    `json:",inline"`
	Description      string              `json:"-"`
	Remediation      string              `json:"-"`
}

type ResourceCounters struct {
	PassedResources   int `json:"passedResources"`
	FailedResources   int `json:"failedResources"`
	ExcludedResources int `json:"excludedResources"`
}

type PostureCounters struct {
	PassedCounter   int `json:"passed"`
	FailedCounter   int `json:"failed"`
	ExcludedCounter int `json:"excluded"`
	SkippedCounter  int `json:"skipped"`
	IgnoredCounter  int `json:"ignored"`
	UnknownCounter  int `json:"unknown"`
}
