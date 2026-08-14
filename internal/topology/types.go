package topology

import (
	"github.com/rancher-sandbox/network-enforcer/internal/ownerkind"
)

type WorkloadKey struct {
	Namespace string
	OwnerKind ownerkind.Kind
	OwnerName string
}
