package reporthandling

import (
	"github.com/armosec/armoapi-go/armotypes"
)

type RuleLanguages string

const (
	RegoLanguage  RuleLanguages = "Rego"
	RegoLanguage2 RuleLanguages = "rego"
)

// RuleMatchObjects defines which objects this rule applied on
type RuleMatchObjects struct {
	APIGroups   []string `json:"apiGroups"`   // apps
	APIVersions []string `json:"apiVersions"` // v1/ v1beta1 / *
	Resources   []string `json:"resources"`   // dep.., pods,
}

// RuleMatchObjects defines which objects this rule applied on
type RuleDependency struct {
	PackageName string `json:"packageName"` // package name
}

type ControlConfigInputs struct {
	Path        string `json:"path"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// PolicyRule represents single rule, the fundamental executable block of policy
type PolicyRule struct {
	armotypes.PortalBase   `json:",inline"`
	CreationTime           string                `json:"creationTime"`
	Rule                   string                `json:"rule"`               // multiline string!
	ResourceEnumerator     string                `json:"resourceEnumerator"` // multiline string!
	RuleLanguage           RuleLanguages         `json:"ruleLanguage"`
	Match                  []RuleMatchObjects    `json:"match"`
	DynamicMatch           []RuleMatchObjects    `json:"dynamicMatch,omitempty"` // DEPRECATED - Added for ks version 136
	RuleDependencies       []RuleDependency      `json:"ruleDependencies"`
	ConfigInputs           []string              `json:"configInputs"`        // DEPRECATED
	ControlConfigInputs    []ControlConfigInputs `json:"controlConfigInputs"` // list of inputs from postureControlInputs in customerConfig for this rule
	Description            string                `json:"description"`
	Remediation            string                `json:"remediation"`
	RuleQuery              string                `json:"ruleQuery"` // default "armo_builtins" - DEPRECATED
	RelevantCloudProviders []string              `json:"relevantCloudProviders"`
}

// Control represents a collection of rules which are combined together to single purpose
type Control struct {
	armotypes.PortalBase `json:",inline"`
	Control_ID           string       `json:"id,omitempty"` // to be Deprecated
	ControlID            string       `json:"controlID"`
	CreationTime         string       `json:"creationTime"`
	Description          string       `json:"description"`
	Remediation          string       `json:"remediation"`
	Rules                []PolicyRule `json:"rules"`
	FrameworkNames       []string     `json:"frameworkNames,omitempty"`
	// for new list of  rules in POST/UPADTE requests
	RulesIDs              *[]string `json:"rulesIDs,omitempty"`
	BaseScore             float32   `json:"baseScore,omitempty"`
	ARMOImprovementFactor float32   `json:"ARMOImprovementFactor,omitempty"`
}

type UpdatedControl struct {
	Control `json:",inline"`
	Rules   []interface{} `json:"rules"`
}

// Framework represents a collection of controls which are combined together to expose comprehensive behavior
type Framework struct {
	armotypes.PortalBase `json:",inline"`
	CreationTime         string    `json:"creationTime"`
	Description          string    `json:"description"`
	Controls             []Control `json:"controls"`
	// for new list of  controls in POST/UPADTE requests
	ControlsIDs *[]string                      `json:"controlsIDs,omitempty"`
	SubSections map[string]FrameworkSubSection `json:"subSections,omitempty"`
}

type UpdatedFramework struct {
	Framework `json:",inline"`
	Controls  []interface{} `json:"controls"`
}

type FrameworkSubSection struct {
	armotypes.PortalBase `json:",inline"`
	ID                   string                         `json:"id"`                    // unique id inside the framework.
	SubSections          map[string]FrameworkSubSection `json:"subSections,omitempty"` // inner subsection
	ControlIDs           []string                       `json:"controlsIDs,omitempty"` // control ids.
	Controls             []*Control                     `json:"-"`                     // controls list for fast access
}
