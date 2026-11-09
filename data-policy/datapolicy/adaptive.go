package datapolicy

import (
	"privacy-protection/adaptive/pkg/reasoning"
)

func loadAdaptiveCoordinator() *reasoning.AdaptiveCoordinator {
	coord, err := reasoning.LoadCoordinatorFromEnv()
	if err != nil {
		return nil
	}
	return coord
}

func (m *EnhancedDataPolicyManager) policyFromDAPP(strategy string) EncryptionPolicy {
	switch strategy {
	case reasoning.DAPPECDH:
		return m.dappPolicies[reasoning.DAPPECDH]
	case reasoning.DAPPSSS:
		return m.dappPolicies[reasoning.DAPPSSS]
	case reasoning.DAPPPRE:
		return m.dappPolicies[reasoning.DAPPPRE]
	case reasoning.DAPPMPC:
		return m.dappPolicies[reasoning.DAPPMPC]
	case reasoning.DAPPPublic:
		return m.dappPolicies[reasoning.DAPPPublic]
	default:
		return nil
	}
}
