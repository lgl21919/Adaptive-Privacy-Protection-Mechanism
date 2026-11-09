package utils

import (
	"github.com/tap-thesis/privacy-protection-identity/internal/db"
	"fmt"
	"sort"
	"strings"
)

func normalizeToken(s string) string {
	return strings.ToUpper(strings.TrimSpace(s))
}

// AnonymityThresholdResult records threshold check outcomes.
type AnonymityThresholdResult struct {
	Threshold   int
	MinSetSize  int
	AvgSetSize  float64
	MaxSetSize  int
	PassRate    float64
	SampleCount int
	Passed      bool
}

// AnonymityScenarioResult is anonymity statistics under one scenario.
type AnonymityScenarioResult struct {
	Phase             string
	ReviewMode        string
	Role              string
	Population        int
	EquivalenceGroups int
	ThresholdCheck    AnonymityThresholdResult
}

// AnonymityMeasurementReport is the full anonymity quantification output.
type AnonymityMeasurementReport struct {
	Threshold int
	Scenarios []AnonymityScenarioResult
}

// MeasureAnonymitySetSizes quantifies anonymity set size from current identity DB.
// If collapsePseudonyms is true, pseudonymous/anonymous users are treated as indistinguishable.
func MeasureAnonymitySetSizes(threshold int, collapsePseudonyms bool) (*AnonymityMeasurementReport, error) {
	allUsers, err := db.GetAllUsers()
	if err != nil {
		return nil, fmt.Errorf("读取用户数据失败: %w", err)
	}

	phaseBuckets := map[string][]db.UserIdentityInfo{
		"SUBMISSION": {},
		"REVIEW":     {},
	}
	for _, u := range allUsers {
		phase := normalizeToken(u.Phase)
		if _, ok := phaseBuckets[phase]; ok {
			phaseBuckets[phase] = append(phaseBuckets[phase], u)
		}
	}

	report := &AnonymityMeasurementReport{
		Threshold: threshold,
		Scenarios: make([]AnonymityScenarioResult, 0),
	}

	for phase, users := range phaseBuckets {
		if len(users) == 0 {
			continue
		}

		scenarios := groupUsersByScenario(users)
		for _, s := range scenarios {
			equiv := map[string]int{}
			for _, u := range s.Users {
				key := observableIdentityKey(u, collapsePseudonyms)
				equiv[key]++
			}

			sizes := make([]int, 0, len(s.Users))
			for _, u := range s.Users {
				key := observableIdentityKey(u, collapsePseudonyms)
				sizes = append(sizes, equiv[key])
			}

			result := buildThresholdResult(sizes, threshold)
			report.Scenarios = append(report.Scenarios, AnonymityScenarioResult{
				Phase:             phase,
				ReviewMode:        s.ReviewMode,
				Role:              s.Role,
				Population:        len(s.Users),
				EquivalenceGroups: len(equiv),
				ThresholdCheck:    result,
			})
		}
	}

	sort.Slice(report.Scenarios, func(i, j int) bool {
		a := report.Scenarios[i]
		b := report.Scenarios[j]
		if a.Phase != b.Phase {
			return a.Phase < b.Phase
		}
		if a.ReviewMode != b.ReviewMode {
			return a.ReviewMode < b.ReviewMode
		}
		return a.Role < b.Role
	})

	return report, nil
}

type scenarioBucket struct {
	Phase      string
	ReviewMode string
	Role       string
	Users      []db.UserIdentityInfo
}

func groupUsersByScenario(users []db.UserIdentityInfo) []scenarioBucket {
	buckets := map[string]*scenarioBucket{}
	for _, u := range users {
		phase := normalizeToken(u.Phase)
		reviewMode := normalizeToken(u.ReviewMode)
		role := normalizeToken(u.Role)
		if phase != "REVIEW" {
			reviewMode = "N/A"
		}
		key := strings.Join([]string{phase, reviewMode, role}, "|")
		if _, ok := buckets[key]; !ok {
			buckets[key] = &scenarioBucket{
				Phase:      phase,
				ReviewMode: reviewMode,
				Role:       role,
				Users:      make([]db.UserIdentityInfo, 0),
			}
		}
		buckets[key].Users = append(buckets[key].Users, u)
	}

	out := make([]scenarioBucket, 0, len(buckets))
	for _, b := range buckets {
		out = append(out, *b)
	}
	return out
}

func observableIdentityKey(u db.UserIdentityInfo, collapsePseudonyms bool) string {
	phase := normalizeToken(u.Phase)
	mode := normalizeToken(u.ReviewMode)
	role := normalizeToken(u.Role)

	visibleIdentityType := "REAL"
	if phase == "REVIEW" {
		switch mode {
		case "DOUBLE_BLIND":
			if role == "AUTHOR" || role == "REVIEWER" {
				visibleIdentityType = "PSEUDONYM"
			}
		case "SINGLE_BLIND":
			if role == "REVIEWER" {
				visibleIdentityType = "PSEUDONYM"
			}
		case "OPEN":
			visibleIdentityType = "REAL"
		default:
			visibleIdentityType = "ANONYMOUS"
		}
	}

	if (visibleIdentityType == "PSEUDONYM" || visibleIdentityType == "ANONYMOUS") && collapsePseudonyms {
		return fmt.Sprintf("%s|%s|%s|INDISTINGUISHABLE", phase, mode, role)
	}

	if visibleIdentityType == "PSEUDONYM" {
		if strings.TrimSpace(u.PhasePseudonym) != "" {
			return fmt.Sprintf("%s|%s|%s|%s", phase, mode, role, u.PhasePseudonym)
		}
		return fmt.Sprintf("%s|%s|%s|%s", phase, mode, role, u.OnChainIdentity)
	}

	return fmt.Sprintf("%s|%s|%s|%s", phase, mode, role, u.OnChainIdentity)
}

func buildThresholdResult(sizes []int, threshold int) AnonymityThresholdResult {
	if len(sizes) == 0 {
		return AnonymityThresholdResult{Threshold: threshold}
	}

	minV := sizes[0]
	maxV := sizes[0]
	sum := 0
	pass := 0
	for _, v := range sizes {
		if v < minV {
			minV = v
		}
		if v > maxV {
			maxV = v
		}
		sum += v
		if v >= threshold {
			pass++
		}
	}
	avg := float64(sum) / float64(len(sizes))
	passRate := float64(pass) / float64(len(sizes)) * 100

	return AnonymityThresholdResult{
		Threshold:   threshold,
		MinSetSize:  minV,
		AvgSetSize:  avg,
		MaxSetSize:  maxV,
		PassRate:    passRate,
		SampleCount: len(sizes),
		Passed:      minV >= threshold,
	}
}
