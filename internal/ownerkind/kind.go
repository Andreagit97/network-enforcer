package ownerkind

type Kind string

const (
	KindDeployment  Kind = "Deployment"
	KindStatefulSet Kind = "StatefulSet"
	KindDaemonSet   Kind = "DaemonSet"
	KindReplicaSet  Kind = "ReplicaSet"
	KindPod         Kind = "Pod"
	KindService     Kind = "Service"
	KindCronJob     Kind = "CronJob"
)

func IsValidEndpoint(kind string) (Kind, bool) {
	k := Kind(kind)
	switch k { //nolint:exhaustive // some kinds like the service are not valid endpoints for now.
	case KindDeployment, KindStatefulSet, KindDaemonSet:
		return k, true
	default:
		return "", false
	}
}
