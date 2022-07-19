package reportsummary

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/opa-utils/reporthandling"
	"github.com/armosec/opa-utils/reporthandling/apis"
	"github.com/armosec/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
)

var mockResultsPassed = resourcesresults.MockResults()[0]
var mockResultsFailed = resourcesresults.MockResults()[1]

func TestRuleStatus(t *testing.T) {
	r := mockSummaryDetailsFailed()
	r.CalculateStatus()

	assert.Equal(t, apis.StatusFailed, r.GetStatus().Status())
	assert.True(t, r.GetStatus().IsFailed())
	assert.False(t, r.GetStatus().IsPassed())
	assert.False(t, r.GetStatus().IsExcluded())
	assert.False(t, r.GetStatus().IsSkipped())

	r1 := mockSummaryDetailsExcluded()
	r1.CalculateStatus()

	assert.Equal(t, apis.StatusExcluded, r1.GetStatus().Status())
	assert.True(t, r1.GetStatus().IsExcluded())
	assert.False(t, r1.GetStatus().IsFailed())
	assert.False(t, r1.GetStatus().IsPassed())
	assert.False(t, r1.GetStatus().IsSkipped())

	r2 := mockSummaryDetailsPassed()
	r2.CalculateStatus()

	assert.Equal(t, apis.StatusPassed, r2.GetStatus().Status())
	assert.True(t, r2.GetStatus().IsPassed())
	assert.False(t, r2.GetStatus().IsFailed())
	assert.False(t, r2.GetStatus().IsExcluded())
	assert.False(t, r2.GetStatus().IsSkipped())

}

func TestRuleListing(t *testing.T) {
	r := mockSummaryDetailsFailed()
	assert.NotEqual(t, 0, len(r.ListFrameworksNames().All()))
	assert.NotEqual(t, 0, len(r.ListFrameworksNames().Failed()))
	assert.NotEqual(t, 0, len(r.ListControlsNames().Failed()))
	assert.NotEqual(t, 0, len(r.ListControlsIDs().Failed()))
}

func TestUpdateControlsSummaryCountersFailed(t *testing.T) {
	controls := map[string]ControlSummary{}

	failedControls := mockResultsFailed.ListControlsIDs(nil).Failed()
	for i := range failedControls {
		controls[failedControls[i]] = ControlSummary{}
	}

	// New control
	updateControlsSummaryCounters(&mockResultsFailed, controls, nil)
	for _, v := range controls {
		assert.Equal(t, 1, v.NumberOfResources().All())
		assert.Equal(t, 1, v.NumberOfResources().Failed())
		assert.Equal(t, 0, v.NumberOfResources().Passed())
		assert.Equal(t, 0, v.NumberOfResources().Skipped())
		assert.Equal(t, 0, v.NumberOfResources().Excluded())
	}

}
func TestUpdateControlsSummaryCountersPassed(t *testing.T) {
	controls := map[string]ControlSummary{}

	passedControls := mockResultsFailed.ListControlsIDs(nil).Passed()
	for i := range passedControls {
		controls[passedControls[i]] = ControlSummary{}
	}

	// New control
	updateControlsSummaryCounters(&mockResultsPassed, controls, nil)
	for _, v := range controls {
		assert.Equal(t, 1, v.NumberOfResources().All())
		assert.Equal(t, 1, v.NumberOfResources().Passed())
		assert.Equal(t, 0, v.NumberOfResources().Failed())
		assert.Equal(t, 0, v.NumberOfResources().Skipped())
		assert.Equal(t, 0, v.NumberOfResources().Excluded())
	}
}

func TestUpdateControlsSummaryCountersAll(t *testing.T) {
	controls := map[string]ControlSummary{}

	allControls := mockResultsFailed.ListControlsIDs(nil)
	tt := allControls.All()
	for i := range tt {
		controls[tt[i]] = ControlSummary{}
	}

	updateControlsSummaryCounters(&mockResultsFailed, controls, nil)
	for _, i := range allControls.Failed() {
		v, k := controls[i]
		assert.True(t, k)
		assert.NotEqual(t, 0, v.NumberOfResources().All())
		assert.NotEqual(t, 0, v.NumberOfResources().Failed())
		assert.Equal(t, 0, v.NumberOfResources().Passed())
		assert.Equal(t, 0, v.NumberOfResources().Skipped())
		assert.Equal(t, 0, v.NumberOfResources().Excluded())
	}
	for _, i := range allControls.Passed() {
		v, k := controls[i]
		assert.True(t, k)
		assert.NotEqual(t, 0, v.NumberOfResources().All())
		assert.NotEqual(t, 0, v.NumberOfResources().Passed())
		assert.Equal(t, 0, v.NumberOfResources().Failed())
		assert.Equal(t, 0, v.NumberOfResources().Skipped())
		assert.Equal(t, 0, v.NumberOfResources().Excluded())
	}
}

func TestSummaryDetails_InitSubsectionsSummary(t *testing.T) {

	// Setup data
	simpleSubsection := reporthandling.FrameworkSubSection{
		PortalBase: armotypes.PortalBase{Name: "root"},
		ID:         "1",
		ControlIDs: []string{
			"C-0011",
			"C-0012",
		},
	}
	simpleFrameworks := []reporthandling.Framework{
		{
			PortalBase: armotypes.PortalBase{
				Name: "simple framework",
			},
			SubSections: map[string]reporthandling.FrameworkSubSection{"1": simpleSubsection},
		},
	}
	nestedSubsection := reporthandling.FrameworkSubSection{
		PortalBase:  armotypes.PortalBase{Name: "parent"},
		ID:          "2",
		SubSections: map[string]reporthandling.FrameworkSubSection{"1": simpleSubsection},
		ControlIDs: []string{
			"C-0015",
			"C-0014",
		},
	}
	nestedFrameworks := []reporthandling.Framework{
		{
			PortalBase:  armotypes.PortalBase{Name: "nested framework"},
			SubSections: map[string]reporthandling.FrameworkSubSection{"2": nestedSubsection},
		},
	}

	// Setup test cases
	type fields struct {
		SummaryDetails *SummaryDetails
	}
	type args struct {
		opaFrameworks  []reporthandling.Framework
		controlInfoMap map[string]apis.StatusInfo
	}
	tests := []struct {
		name     string
		fields   fields
		args     args
		expected []FrameworkSubsectionSummary
	}{
		{
			name:   "simple passed",
			fields: fields{SummaryDetails: MockSummaryDetails()},
			args: args{
				opaFrameworks: simpleFrameworks,
				controlInfoMap: map[string]apis.StatusInfo{
					"C-0011": {InnerStatus: apis.StatusPassed},
					"C-0012": {InnerStatus: apis.StatusPassed},
					"C-0013": {InnerStatus: apis.StatusPassed},
				},
			},
			expected: []FrameworkSubsectionSummary{
				{
					Name:      "root",
					Framework: "simple framework",
					ID:        "1",
					ControlsStats: map[apis.ScanningStatus]uint{
						apis.StatusPassed: 2,
					},
				},
			},
		},
		{
			name:   "simple mixed",
			fields: fields{SummaryDetails: MockSummaryDetails()},
			args: args{
				opaFrameworks: simpleFrameworks,
				controlInfoMap: map[string]apis.StatusInfo{
					"C-0011": {InnerStatus: apis.StatusPassed},
					"C-0012": {InnerStatus: apis.StatusFailed},
					"C-0013": {InnerStatus: apis.StatusPassed},
				},
			},
			expected: []FrameworkSubsectionSummary{
				{
					Name:      "root",
					Framework: "simple framework",
					ID:        "1",
					ControlsStats: map[apis.ScanningStatus]uint{
						apis.StatusPassed: 1,
						apis.StatusFailed: 1,
					},
				},
			},
		},
		{
			name:   "nested passed",
			fields: fields{SummaryDetails: MockSummaryDetails()},
			args: args{
				opaFrameworks: nestedFrameworks,
				controlInfoMap: map[string]apis.StatusInfo{
					"C-0011": {InnerStatus: apis.StatusPassed},
					"C-0012": {InnerStatus: apis.StatusPassed},
					"C-0013": {InnerStatus: apis.StatusPassed},
					"C-0014": {InnerStatus: apis.StatusPassed},
				},
			},
			expected: []FrameworkSubsectionSummary{
				{
					Name:      "root",
					Framework: "nested framework",
					ID:        "1",
					ControlsStats: map[apis.ScanningStatus]uint{
						apis.StatusPassed: 2,
					},
				},
				{
					Name:      "parent",
					Framework: "nested framework",
					ID:        "2",
					ControlsStats: map[apis.ScanningStatus]uint{
						apis.StatusPassed: 3,
					},
				},
			},
		},
		{
			name:   "nested mixed",
			fields: fields{SummaryDetails: MockSummaryDetails()},
			args: args{
				opaFrameworks: nestedFrameworks,
				controlInfoMap: map[string]apis.StatusInfo{
					"C-0011": {InnerStatus: apis.StatusPassed},
					"C-0012": {InnerStatus: apis.StatusFailed},
					"C-0013": {InnerStatus: apis.StatusExcluded},
					"C-0014": {InnerStatus: apis.StatusIgnored},
					"C-0015": {InnerStatus: apis.StatusError},
				},
			},
			expected: []FrameworkSubsectionSummary{
				{
					Name:      "root",
					Framework: "nested framework",
					ID:        "1",
					ControlsStats: map[apis.ScanningStatus]uint{
						apis.StatusPassed: 1,
						apis.StatusFailed: 1,
					},
				},
				{
					Name:      "parent",
					Framework: "nested framework",
					ID:        "2",
					ControlsStats: map[apis.ScanningStatus]uint{
						apis.StatusPassed:  1,
						apis.StatusFailed:  1,
						apis.StatusIgnored: 1,
						apis.StatusError:   1,
					},
				},
			},
		},
	}

	// Run tests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.fields.SummaryDetails.InitSubsectionsSummary(tt.args.opaFrameworks, tt.args.controlInfoMap)
			for i, summary := range tt.fields.SummaryDetails.FrameworksSubsections {
				assert.Equal(t, tt.expected[i].Name, summary.Name)
				assert.Equal(t, tt.expected[i].ID, summary.ID)
				assert.Equal(t, tt.expected[i].Framework, summary.Framework)
				assert.Equal(t, len(tt.expected[i].ControlsStats), len(summary.ControlsStats))
				for status := range summary.ControlsStats {
					assert.Equal(t, tt.expected[i].ControlsStats[status], summary.ControlsStats[status])
				}
			}
		})
	}
}
