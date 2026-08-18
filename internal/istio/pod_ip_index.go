package istio

import (
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// PodIPIndexField is the field-index key used to resolve a Pod by its
// status.podIP. Istio violation events identify the client only by peer
// address, so the source workload is resolved by listing pods on this index.
// The index itself is registered on the manager by controller.SetupPodIPIndexer.
const PodIPIndexField = "status.podIP"

// IndexPodByIP extracts a Pod's status.podIP for the field indexer. Pods
// without an assigned IP are not indexed. Both the manager (via
// controller.SetupPodIPIndexer) and the unit tests register this exact function
// so the index behaves identically in production and in fake clients.
func IndexPodByIP(o client.Object) []string {
	pod, ok := o.(*corev1.Pod)
	if !ok || pod.Status.PodIP == "" {
		return nil
	}
	return []string{pod.Status.PodIP}
}
