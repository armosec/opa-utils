package gitregostore

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	// "github.com/armosec/capacketsgo/opapolicy"
	"github.com/armosec/armoapi-go/armotypes"
	opapolicy "github.com/armosec/opa-utils/reporthandling"
	"github.com/go-gota/gota/dataframe"
	"go.uber.org/zap"
)

type storeSetter func(*GitRegoStore, string) error

const (
	frameworksJsonFileName            = "frameworks"
	controlsJsonFileName              = "controls"
	rulesJsonFileName                 = "rules"
	frameworkControlRelationsFileName = "FWName_CID_CName"
	ControlRuleRelationsFileName      = "ControlID_RuleName"
	defaultConfigInputsFileName       = "default_config_inputs"

	controlIDRegex = `^(?:[a-z]+|[A-Z]+)(?:[\-][v]?(?:[0-9][\.]?)+)(?:[\-]?[0-9][\.]?)+$`
)

var controlIDRegexCompiled *regexp.Regexp = nil

var storeSetterMapping = map[string]storeSetter{
	frameworksJsonFileName:            (*GitRegoStore).setFrameworks,
	controlsJsonFileName:              (*GitRegoStore).setControls,
	rulesJsonFileName:                 (*GitRegoStore).setRules,
	frameworkControlRelationsFileName: (*GitRegoStore).setFrameworkControlRelations,
	ControlRuleRelationsFileName:      (*GitRegoStore).setControlRuleRelations,
	defaultConfigInputsFileName:       (*GitRegoStore).setDefaultConfigInputs,
}

type InnerTree []struct {
	PATH string `json:"path"`
}
type Tree struct {
	TREE InnerTree `json:"tree"`
}

// func setURL()
func (gs *GitRegoStore) setURL() {
	var url string

	if isUrlRelease(gs.Path) {
		url = gs.BaseUrl + "/" + gs.Owner + "/" + gs.Repository + "/" + gs.Path + "/" + gs.Tag
	} else {
		url = gs.BaseUrl + "/" + gs.Owner + "/" + gs.Repository + "/" + gs.Path + "/" + gs.Branch + "?recursive=1"
	}
	gs.URL = url
}

func (gs *GitRegoStore) setObjects() error {
	var err error
	if isUrlRelease(gs.URL) {
		err = gs.setObjectsFromReleaseLoop()
	} else {
		err = gs.setObjectsFromRepoLoop()
	}
	return err
}

func isUrlRelease(u string) bool {
	return strings.Contains(u, "releases")
}

// ========================== set Objects From Repo =====================================

func (gs *GitRegoStore) setObjectsFromRepoLoop() error {
	var wg sync.WaitGroup
	wg.Add(1)
	var e error

	go func() {
		f := true
		for {
			if err := gs.setObjectsFromRepoOnce(); err != nil {
				e = err
			}
			if f {
				wg.Done() // first update to done
				f = false
			}
			if !gs.Watch {
				return
			}
			time.Sleep(time.Duration(gs.FrequencyPullFromGitMinutes) * time.Minute)
		}
	}()
	wg.Wait()
	return e
}

func (gs *GitRegoStore) setObjectsFromRepoOnce() error {
	body, err := HttpGetter(gs.httpClient, gs.URL)
	if err != nil {
		return err
	}
	var trees Tree
	err = json.Unmarshal([]byte(body), &trees)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response body from '%s', reason: %s", gs.URL, err.Error())
	}
	gs.frameworksLock.Lock()
	gs.controlsLock.Lock()
	gs.rulesLock.Lock()
	defer gs.frameworksLock.Unlock()
	defer gs.controlsLock.Unlock()
	defer gs.rulesLock.Unlock()
	gs.Frameworks = []opapolicy.Framework{}
	gs.Controls = []opapolicy.Control{}
	gs.Rules = []opapolicy.PolicyRule{}

	// use only json files from relevant dirs
	for _, path := range trees.TREE {
		rawDataPath := "https://raw.githubusercontent.com/" + gs.Owner + "/" + gs.Repository + "/" + gs.Branch + "/" + path.PATH

		if strings.HasPrefix(path.PATH, rulesJsonFileName+"/") && strings.HasSuffix(path.PATH, ".json") {
			respStr, err := HttpGetter(gs.httpClient, rawDataPath)
			if err != nil {
				return err
			}
			if err := gs.setRulesWithRawRego(respStr, rawDataPath); err != nil {
				zap.L().Debug("In setObjectsFromRepoOnce - failed to set rule %s\n", zap.String("path", rawDataPath))
				return err
			}
		} else if strings.HasPrefix(path.PATH, controlsJsonFileName+"/") && strings.HasSuffix(path.PATH, ".json") {
			respStr, err := HttpGetter(gs.httpClient, rawDataPath)
			if err != nil {
				return err
			}
			if err := gs.setControl(respStr); err != nil {
				zap.L().Debug("In setObjectsFromRepoOnce - failed to set control %s\n", zap.String("path", rawDataPath))
				return err
			}
		} else if strings.HasPrefix(path.PATH, frameworksJsonFileName+"/") && strings.HasSuffix(path.PATH, ".json") {
			respStr, err := HttpGetter(gs.httpClient, rawDataPath)
			if err != nil {
				return err
			}
			if err := gs.setFramework(respStr); err != nil {
				zap.L().Debug("In setObjectsFromRepoOnce - failed to set framework %s\n", zap.String("path", rawDataPath))
				return err
			}
		} else if strings.HasPrefix(path.PATH, defaultConfigInputsFileName) && strings.HasSuffix(path.PATH, ".json") {
			respStr, err := HttpGetter(gs.httpClient, rawDataPath)
			if err != nil {
				return err
			}
			if err := gs.setDefaultConfigInputs(respStr); err != nil {
				zap.L().Debug("In setObjectsFromRepoOnce - failed to set DefaultConfigInputs %s\n", zap.String("path", rawDataPath))
				return err
			}
		} else if strings.HasSuffix(path.PATH, ControlRuleRelationsFileName+".csv") {
			respStr, err := HttpGetter(gs.httpClient, rawDataPath)
			if err != nil {
				return err
			}
			gs.setControlRuleRelations(respStr)
		} else if strings.HasSuffix(path.PATH, frameworkControlRelationsFileName+".csv") {
			respStr, err := HttpGetter(gs.httpClient, rawDataPath)
			if err != nil {
				return err
			}
			gs.setFrameworkControlRelations(respStr)
		}
	}
	return nil
}

func (gs *GitRegoStore) setFramework(respStr string) error {
	framework := &opapolicy.Framework{}
	if err := JSONDecoder(respStr).Decode(framework); err != nil {
		return err
	}
	gs.Frameworks = append(gs.Frameworks, *framework)
	return nil
}

func (gs *GitRegoStore) setControl(respStr string) error {
	control := &opapolicy.Control{}
	if err := JSONDecoder(respStr).Decode(control); err != nil {
		return err
	}
	gs.Controls = append(gs.Controls, *control)
	return nil
}

func (gs *GitRegoStore) setRulesWithRawRego(respStr string, path string) error {
	rule := &opapolicy.PolicyRule{}
	rawRego, err := gs.getRulesWithRawRego(rule, respStr, path)
	if err != nil {
		return err
	}
	filterRego, err := gs.getRulesWithFilterRego(rule, respStr, path)
	if err != nil && !strings.Contains(err.Error(), "404 Not Found") {
		return err
	}
	rule.Rule = rawRego
	rule.ResourceEnumerator = filterRego
	gs.Rules = append(gs.Rules, *rule)
	return nil
}

func (gs *GitRegoStore) getRulesWithRawRego(rule *opapolicy.PolicyRule, respStr string, path string) (string, error) {
	if err := JSONDecoder(respStr).Decode(rule); err != nil {
		return "", err
	}
	rawRegoPath := path[:strings.LastIndex(path, "/")] + "/raw.rego"
	respString, err := HttpGetter(gs.httpClient, rawRegoPath)
	if err != nil {
		return "", err
	}
	return respString, nil
}

func (gs *GitRegoStore) getRulesWithFilterRego(rule *opapolicy.PolicyRule, respStr string, path string) (string, error) {
	if err := JSONDecoder(respStr).Decode(rule); err != nil {
		return "", err
	}
	rawRegoPath := path[:strings.LastIndex(path, "/")] + "/filter.rego"
	respString, err := HttpGetter(gs.httpClient, rawRegoPath)
	if err != nil {
		return "", err
	}
	return respString, nil
}

// ======================== set Objects From Release =============================================

func (gs *GitRegoStore) setObjectsFromReleaseLoop() error {
	var wg sync.WaitGroup
	wg.Add(1)
	var e error
	go func() {
		f := true
		for {
			if err := gs.setObjectsFromReleaseOnce(); err != nil {
				e = err
			}
			if f {
				wg.Done() // first update to done
				f = false
			}
			if !gs.Watch {
				return
			}
			time.Sleep(time.Duration(gs.FrequencyPullFromGitMinutes) * time.Minute)
		}
	}()
	wg.Wait()
	return e
}

func (gs *GitRegoStore) setObjectsFromReleaseOnce() error {

	for kind, storeSetterMappingFunc := range storeSetterMapping {
		respStr, err := HttpGetter(gs.httpClient, fmt.Sprintf("%s/%s", gs.URL, kind))
		if err != nil {
			return fmt.Errorf("error getting: %s from: '%s' ,error: %s", kind, gs.URL, err)
		}
		if err = storeSetterMappingFunc(gs, respStr); err != nil {
			return err
		}
	}
	return nil
}

func (gs *GitRegoStore) setFrameworks(respStr string) error {
	frameworks := []opapolicy.Framework{}
	if err := JSONDecoder(respStr).Decode(&frameworks); err != nil {
		return err
	}
	gs.frameworksLock.Lock()
	defer gs.frameworksLock.Unlock()
	gs.Frameworks = frameworks
	return nil
}

func (gs *GitRegoStore) setControls(respStr string) error {
	controls := []opapolicy.Control{}
	if err := JSONDecoder(respStr).Decode(&controls); err != nil {
		return err
	}
	gs.controlsLock.Lock()
	defer gs.controlsLock.Unlock()
	gs.Controls = controls
	return nil
}

func (gs *GitRegoStore) setRules(respStr string) error {
	rules := &[]opapolicy.PolicyRule{}
	if err := JSONDecoder(respStr).Decode(rules); err != nil {
		return err
	}
	gs.rulesLock.Lock()
	defer gs.rulesLock.Unlock()
	gs.Rules = *rules
	return nil
}
func (gs *GitRegoStore) setDefaultConfigInputs(respStr string) error {
	defaultConfigInputs := armotypes.CustomerConfig{}
	if err := JSONDecoder(respStr).Decode(&defaultConfigInputs); err != nil {
		return err
	}
	gs.DefaultConfigInputsLock.Lock()
	defer gs.DefaultConfigInputsLock.Unlock()
	gs.DefaultConfigInputs = defaultConfigInputs
	return nil
}

func (gs *GitRegoStore) setFrameworkControlRelations(respStr string) error {
	df := dataframe.ReadCSV(strings.NewReader(respStr))
	gs.FrameworkControlRelations = df
	return nil
}

func (gs *GitRegoStore) setControlRuleRelations(respStr string) error {
	df := dataframe.ReadCSV(strings.NewReader(respStr))
	gs.ControlRuleRelations = df
	return nil
}

// JSONDecoder returns JSON decoder for given string
func JSONDecoder(origin string) *json.Decoder {
	dec := json.NewDecoder(strings.NewReader(origin))
	dec.UseNumber()
	return dec
}

func HttpGetter(httpClient *http.Client, fullURL string) (string, error) {
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	respStr, err := HTTPRespToString(resp)
	if err != nil {
		return "", err
	}
	return respStr, nil
}

// HTTPRespToString parses the body as string and checks the HTTP status code, it closes the body reader at the end
// TODO: FIX BUG: status code is not being checked when the body is empty
func HTTPRespToString(resp *http.Response) (string, error) {
	if resp == nil || resp.Body == nil {
		return "", nil
	}
	strBuilder := strings.Builder{}
	defer resp.Body.Close()
	if resp.ContentLength > 0 {
		strBuilder.Grow(int(resp.ContentLength))
	}
	bytesNum, err := io.Copy(&strBuilder, resp.Body)
	respStr := strBuilder.String()
	if err != nil {
		respStrNewLen := len(respStr)
		if respStrNewLen > 1024 {
			respStrNewLen = 1024
		}
		return "", fmt.Errorf("HTTP request failed. URL: '%s', Read-ERROR: '%s', HTTP-CODE: '%s', BODY(top): '%s', HTTP-HEADERS: %v, HTTP-BODY-BUFFER-LENGTH: %v", resp.Request.URL.RequestURI(), err, resp.Status, respStr[:respStrNewLen], resp.Header, bytesNum)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respStrNewLen := len(respStr)
		if respStrNewLen > 1024 {
			respStrNewLen = 1024
		}
		err = fmt.Errorf("HTTP request failed. URL: '%s', HTTP-ERROR: '%s', BODY: '%s', HTTP-HEADERS: %v, HTTP-BODY-BUFFER-LENGTH: %v", resp.Request.URL.RequestURI(), resp.Status, respStr[:respStrNewLen], resp.Header, bytesNum)
	}
	zap.L().Debug("In HTTPRespToString - request end succesfully",
		zap.String("URL", resp.Request.URL.String()), zap.Int("contentLength", int(resp.ContentLength)))

	return respStr, err
}

func isControlID(c string) bool {

	// Compile regex only once
	if controlIDRegexCompiled == nil {
		compiled, err := regexp.Compile(controlIDRegex)
		if err != nil {
			return false
		}
		controlIDRegexCompiled = compiled
	}

	// Match
	return controlIDRegexCompiled.MatchString(c)
}
