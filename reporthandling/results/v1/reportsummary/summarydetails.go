package reportsummary

import (
	"github.com/armosec/opa-utils/reporthandling"
	"github.com/armosec/opa-utils/reporthandling/apis"
	helpersv1 "github.com/armosec/opa-utils/reporthandling/helpers/v1"
	"github.com/armosec/opa-utils/reporthandling/results/v1/resourcesresults"
)

// =================================== Status ============================================

// Status get the scan status. returns an apis.ScanningStatus object
func (summaryDetails *SummaryDetails) GetStatus() *helpersv1.Status {
	if summaryDetails.Status == apis.StatusUnknown {
		summaryDetails.CalculateStatus()
	}
	return helpersv1.NewStatus(summaryDetails.Status)
}

// GetScore return score
func (summaryDetails *SummaryDetails) GetScore() float32 {
	return summaryDetails.Score
}

// SetStatus set the framework status based on the resource counters
func (summaryDetails *SummaryDetails) CalculateStatus() {
	summaryDetails.Status = calculateStatus(&summaryDetails.ResourceCounters)
}

// =================================== Counters ============================================

// NumberOfExcluded get the number of excluded resources
func (summaryDetails *SummaryDetails) NumberOfResources() ICounters {
	return &summaryDetails.ResourceCounters
}

// Increase increases the counter based on the status
func (summaryDetails *SummaryDetails) Increase(status apis.IStatus) {
	summaryDetails.ResourceCounters.Increase(status)
}

// InitResourcesSummary must run this AFTER initializing the controls
func (summaryDetails *SummaryDetails) InitResourcesSummary(controlInfoMap map[string]apis.StatusInfo) {
	for i := range summaryDetails.Frameworks {
		summaryDetails.Frameworks[i].initResourcesSummary(controlInfoMap)
	}

	for k, control := range summaryDetails.Controls {
		if statusInfo, ok := controlInfoMap[control.ControlID]; ok && statusInfo.InnerStatus != apis.StatusUnknown {
			control.SetStatus(&statusInfo)
		} else if control.GetStatus().Status() == apis.StatusUnknown {
			control.CalculateStatus()
		}
		summaryDetails.Controls[k] = control
	}

	summaryDetails.ResourceCounters.Set(summaryDetails.Controls.ListResourcesIDs())
	summaryDetails.CalculateStatus()
}

// initResourcesSummary must run this AFTER initializing the controls
func (summaryDetails *SummaryDetails) InitSubsectionsSummary(opaFrameworks []reporthandling.Framework, controlInfoMap map[string]apis.StatusInfo) {
	for i := range opaFrameworks {
		fw := &(opaFrameworks[i])
		if len(fw.SubSections) == 0 {
			continue
		}
		for k := range fw.SubSections {
			summaryDetails.summarizeSubSection(fw.Name, fw.SubSections[k], controlInfoMap)
		}
	}
}

// summarizeSubSection RECURSIVLY iterate over subsection controls and adds the summaries to summaryDetails
func (summaryDetails *SummaryDetails) summarizeSubSection(framework string, section reporthandling.FrameworkSubSection, controlInfoMap map[string]apis.StatusInfo) map[string]apis.StatusInfo {
	ctrls := map[string]apis.StatusInfo{}

	// Root-section controls statuses
	if len(section.ControlIDs) > 0 {
		for _, id := range section.ControlIDs {
			if status, ok := controlInfoMap[id]; ok {
				ctrls[id] = status
			}
		}
	}

	// Children controls statuses using recursion
	if len(section.SubSections) > 0 {
		for i := range section.SubSections {
			childCtrls := summaryDetails.summarizeSubSection(framework, section.SubSections[i], controlInfoMap)
			for id := range childCtrls {
				ctrls[id] = childCtrls[i]
			}
		}
	}

	// Controls stats
	ctrlStats := map[apis.ScanningStatus]uint{}
	for _, status := range ctrls {
		ctrlStats[status.Status()]++
	}

	// Summary
	summary := FrameworkSubsectionSummary{
		Name:          section.Name,
		Framework:     framework,
		ID:            section.ID,
		ControlsStats: ctrlStats,
	}
	summaryDetails.FrameworksSubsections = append(summaryDetails.FrameworksSubsections, summary)

	return ctrls
}

// =========================================== List Frameworks ====================================

// ListFrameworksNames list all framework names
func (summaryDetails *SummaryDetails) ListFrameworksNames() *helpersv1.AllLists {
	frameworks := &helpersv1.AllLists{}
	for i := range summaryDetails.Frameworks {
		frameworks.Append(summaryDetails.Frameworks[i].GetStatus().Status(), summaryDetails.Frameworks[i].GetName())
	}
	return frameworks
}

// ListFrameworks list all frameworks
func (summaryDetails *SummaryDetails) ListFrameworks() []IFrameworkSummary {
	frameworks := []IFrameworkSummary{}
	for i := range summaryDetails.Frameworks {
		frameworks = append(frameworks, &summaryDetails.Frameworks[i])
	}
	return frameworks
}

// =========================================== List Controls ====================================

// ListControlsNames list all framework names
func (summaryDetails *SummaryDetails) ListControlsNames() *helpersv1.AllLists {
	controls := &helpersv1.AllLists{}
	for _, controlSummary := range summaryDetails.Controls {
		controls.Append(controlSummary.GetStatus().Status(), controlSummary.Name)
	}
	return controls
}

func (summaryDetails *SummaryDetails) ListControlsIDs() *helpersv1.AllLists {
	controls := &helpersv1.AllLists{}
	for controlID, controlSummary := range summaryDetails.Controls {
		controls.Append(controlSummary.GetStatus().Status(), controlID)
	}
	return controls
}

// ListControls list all controls
func (summaryDetails *SummaryDetails) ListControls() []IControlSummary {
	controls := make([]IControlSummary, len(summaryDetails.Controls))
	for i, id := range summaryDetails.Controls.ListControlsIDs().All() {
		controls[i] = summaryDetails.Controls.GetControl(EControlCriteriaID, id)
	}
	return controls
}

//NumberOfControls get number of controls
func (summaryDetails *SummaryDetails) NumberOfControls() ICounters {

	return &PostureCounters{
		PassedCounter:   len(summaryDetails.ListControlsIDs().Passed()),
		FailedCounter:   len(summaryDetails.ListControlsIDs().Failed()),
		ExcludedCounter: len(summaryDetails.ListControlsIDs().Excluded()),
		SkippedCounter:  len(summaryDetails.ListControlsIDs().Skipped()),
		UnknownCounter:  len(summaryDetails.ListControlsIDs().Other()),
	}
}

// ================================================================================
func (summaryDetails *SummaryDetails) ControlName(controlID string) string {
	if c, ok := summaryDetails.Controls[controlID]; ok {
		return c.Name
	}
	return ""
}

// ListResourcesIDs list all resources IDs
func (summaryDetails *SummaryDetails) ListResourcesIDs() *helpersv1.AllLists {
	return summaryDetails.Controls.ListResourcesIDs()
}

// updateSummaryWithResource get the result of a single resource. If resource not found will return nil
func (summaryDetails *SummaryDetails) AppendResourceResult(resourceResult *resourcesresults.Result) {

	// update full-summary counter
	updateControlsSummaryCounters(resourceResult, summaryDetails.Controls, nil)

	// update frameworks counters
	for _, framework := range summaryDetails.Frameworks {
		updateControlsSummaryCounters(resourceResult, framework.Controls, &helpersv1.Filters{FrameworkNames: []string{framework.Name}})
		framework.CalculateStatus()
	}
}

func updateControlsSummaryCounters(resourceResult *resourcesresults.Result, controls map[string]ControlSummary, f *helpersv1.Filters) {
	// update controls counters
	for i := range resourceResult.AssociatedControls {
		controlID := resourceResult.AssociatedControls[i].ControlID
		if controlSummary, ok := controls[controlID]; ok {
			controlSummary.Append(resourceResult.AssociatedControls[i].GetStatus(f), resourceResult.ResourceID)
			controlSummary.CalculateStatus()
			controls[controlID] = controlSummary
		}
	}
}
