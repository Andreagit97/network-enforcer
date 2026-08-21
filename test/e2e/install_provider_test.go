package e2e_test

import (
	"context"
	"fmt"

	netypes "github.com/rancher-sandbox/network-enforcer/internal/types"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

// installProvider sets up the data-plane provider selected via
// E2E_PROVIDER.
func installProvider() env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		switch getSuiteConfig(ctx).ProviderName() {
		case string(netypes.ProviderIstio):
			return installIstioMesh()(ctx, cfg)
		case string(netypes.ProviderCilium):
			return installCilium(ctx, cfg)
		case string(netypes.ProviderCalico):
			return installCalico(ctx, cfg)
		default:
			return ctx, fmt.Errorf("unsupported provider: %q", getSuiteConfig(ctx).ProviderName())
		}
	}
}
