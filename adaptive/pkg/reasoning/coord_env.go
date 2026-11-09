package reasoning

import (
	"os"
	"sync"
)

const EnvAdaptiveRulesPath = "ADAPTIVE_RULES_PATH"

var (
	envCoordMu   sync.Mutex
	envCoord     *AdaptiveCoordinator
	envCoordPath string // path used for current singleton ("" = DefaultRuleSet)

	sharedWeightsMu sync.Mutex
	sharedWeights   *PolicyWeightStore
)

// SharedPolicyWeights returns the process-wide security-weight store used by
// production coordinators and FeedbackGovernor. Governor/monitor updates here
// immediately affect hot-path Evaluate* selection.
func SharedPolicyWeights() *PolicyWeightStore {
	sharedWeightsMu.Lock()
	defer sharedWeightsMu.Unlock()
	if sharedWeights == nil {
		sharedWeights = NewPolicyWeightStore()
	}
	return sharedWeights
}

// SetSharedPolicyWeights replaces the process-wide store (tests).
func SetSharedPolicyWeights(w *PolicyWeightStore) {
	sharedWeightsMu.Lock()
	defer sharedWeightsMu.Unlock()
	if w == nil {
		w = NewPolicyWeightStore()
	}
	sharedWeights = w
}

// LoadCoordinatorFromEnv returns the process-wide AdaptiveCoordinator used by
// production (identity-policy / data-policy) and UC audit π under golden mode.
//
//	ADAPTIVE_RULES_PATH set → NewCoordinatorFromFile(path)
//	unset / load error     → NewDefaultCoordinator()
//
// Repeated calls return the same instance until ResetCoordinatorFromEnv.
func LoadCoordinatorFromEnv() (*AdaptiveCoordinator, error) {
	envCoordMu.Lock()
	defer envCoordMu.Unlock()
	if envCoord != nil {
		return envCoord, nil
	}
	path := os.Getenv(EnvAdaptiveRulesPath)
	var coord *AdaptiveCoordinator
	var err error
	if path != "" {
		coord, err = NewCoordinatorFromFile(path)
		if err != nil {
			// Match prior production behaviour: bad path falls back to DefaultRuleSet.
			path = ""
			coord = nil
		}
	}
	if coord == nil {
		coord, err = NewDefaultCoordinator()
		if err != nil {
			return nil, err
		}
	}
	coord.AttachWeights(SharedPolicyWeights())
	envCoord = coord
	envCoordPath = path
	return envCoord, nil
}

// CoordinatorEnvPath reports which rules source the singleton was built from.
// Empty string means built-in DefaultRuleSet.
func CoordinatorEnvPath() string {
	envCoordMu.Lock()
	defer envCoordMu.Unlock()
	return envCoordPath
}

// ResetCoordinatorFromEnv clears the singleton so the next LoadCoordinatorFromEnv
// re-reads the environment (tests / hot reload after ops changes YAML path).
func ResetCoordinatorFromEnv() {
	envCoordMu.Lock()
	defer envCoordMu.Unlock()
	envCoord = nil
	envCoordPath = ""
}
