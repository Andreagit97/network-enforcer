# Setup

## Kind + tilt

```bash
# E2E_CNI could be `calico` or `cilium`
# setup-dev-cluster will internally call `tilt up`
make setup-dev-cluster E2E_CNI=calico
```

Teardown

```bash
make delete-dev-cluster
```
