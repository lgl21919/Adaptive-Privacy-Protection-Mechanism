package identitypolicy

import (
	"privacy-protection/adaptive/pkg/reasoning"
	"github.com/tap-thesis/privacy-protection-identity/pkg/types"
)

// loadAdaptiveCoordinator uses the process-wide coordinator shared with
// data-policy and UC audit π (golden mode).
func loadAdaptiveCoordinator() *reasoning.AdaptiveCoordinator {
	coord, err := reasoning.LoadCoordinatorFromEnv()
	if err != nil {
		return nil
	}
	return coord
}

// mapIAPPToVisibility converts IAPP strategy token to IdentityVisibility.
func mapIAPPToVisibility(strategy string) types.IdentityVisibility {
	switch strategy {
	case reasoning.IAPPReal:
		return types.VisibilityReal
	case reasoning.IAPPPseudonym:
		return types.VisibilityPseudonym
	case reasoning.IAPPAnonymous:
		return types.VisibilityAnonymous
	default:
		return types.VisibilityAnonymous
	}
}
