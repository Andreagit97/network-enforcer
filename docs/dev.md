# Setup

## Kind + tilt

```bash
# E2E_PROVIDER could be `istio`, `calico` or `cilium`
# setup-dev-cluster will internally call `tilt up`
make setup-dev-cluster E2E_PROVIDER=istio
```

Teardown

```bash
make delete-dev-cluster
```
