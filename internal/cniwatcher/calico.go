package cniwatcher

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	pb "github.com/rancher-sandbox/network-enforcer/internal/cniwatcher/calico/goldmane"
	"github.com/rancher-sandbox/network-enforcer/internal/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	certDir = "/etc/goldmane/certs"
)

const calicoAggregationInterval = 15 // seconds

type CalicoWatcher struct {
	Watcher

	ConnEndpoint string
	Client       pb.FlowsClient
	conn         *grpc.ClientConn
}

func NewCalicoWatcher(watcher Watcher, connEndpoint string) (*CalicoWatcher, error) {
	return &CalicoWatcher{Watcher: watcher, ConnEndpoint: connEndpoint}, nil
}

func (w *CalicoWatcher) Start() error {
	w.Log.Info("Starting Calico cniWatcher")

	return w.RetryConnectAndWatchFlows(
		w.ConnectToGoldmane,
		func() error {
			if w.conn != nil && w.Client != nil {
				return w.WatchFlows()
			}
			return errors.New("not connected to Goldmane")
		},
		"Calico cniWatcher",
	)
}

func (w *CalicoWatcher) ConnectToGoldmane() error {
	clientCertPath := filepath.Join(certDir, "tls.crt")
	clientKeyPath := filepath.Join(certDir, "tls.key")
	caCertPath := filepath.Join(certDir, "ca.crt")

	clientCert, err := os.ReadFile(clientCertPath)
	if err != nil {
		return fmt.Errorf("failed to read client certificate: %w", err)
	}
	clientKey, err := os.ReadFile(clientKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read client key: %w", err)
	}
	cert, err := tls.X509KeyPair(clientCert, clientKey)
	if err != nil {
		return fmt.Errorf("failed to load client certificate and key: %w", err)
	}

	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return errors.New("failed to append CA certificate")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	creds := credentials.NewTLS(tlsConfig)
	w.Log.Info("Using TLS credentials for Goldmane connection")

	conn, connErr := grpc.NewClient(
		w.ConnEndpoint,
		grpc.WithTransportCredentials(creds),
	)

	if connErr != nil {
		return fmt.Errorf("failed to connect to Goldmane: %w", connErr)
	}

	w.conn = conn
	w.Client = pb.NewFlowsClient(conn)
	w.Log.Info("Successfully connected to Goldmane", "endpoint", w.ConnEndpoint)

	return nil
}

func (w *CalicoWatcher) WatchFlows() error {
	// filter := &pb.Filter{
	// 	Actions: []pb.Action{pb.Action_Deny},
	// }

	req := &pb.FlowStreamRequest{
		StartTimeGte: 0,
		// Filter:              filter,
		AggregationInterval: calicoAggregationInterval, // 15 seconds is the required value
	}

	w.Log.Info("Starting to watch Calico policy deny events from Goldmane")
	stream, err := w.Client.Stream(w.Ctx, req)
	if err != nil {
		return fmt.Errorf("failed to stream flows from Goldmane: %w", err)
	}

	for {
		select {
		case <-w.Ctx.Done():
			w.Log.Info("Calico cniWatcher shutting down due to context cancel")
			return nil
		default:
			flowResult, recvErr := stream.Recv()
			if recvErr != nil {
				return fmt.Errorf("error receiving flow from Goldmane: %w", recvErr)
			}

			event, parseErr := w.parsePolicyDenyEvent(flowResult)
			if parseErr != nil {
				w.Log.Error("failed to parse policy deny event", "flowResult", flowResult, "err", parseErr)
				continue
			}
			if processErr := w.ProcessPolicyDenyEvent(event); processErr != nil {
				w.Log.Error("failed to process policy deny event", "event", event, "err", processErr)
			}
		}
	}
}

// parsePolicyDenyEvent parses Calico Goldmane flow results and extracts policy deny events.
// It processes flow results and filters for flows with "Action_Deny".
//
// The function may return (nil, nil) when the flow action is not "Action_Deny" (e.g., "Action_Allow").
// This is not an error condition but indicates the flow should be skipped.
//
// Returns:
//   - (*types.PolicyDenyEvent, nil): Successfully parsed policy deny event
//   - (nil, error): Failed to parse the flow (nil flowResult, nil flow, nil key, etc.)
//   - (nil, nil): Not a policy deny event (should be skipped)
func (w *CalicoWatcher) parsePolicyDenyEvent(flowResult *pb.FlowResult) (*types.PolicyDenyEvent, error) {
	if flowResult == nil {
		return nil, errors.New("flowResult is nil")
	}

	flow := flowResult.GetFlow()
	if flow == nil {
		return nil, errors.New("flow is nil")
	}

	key := flow.GetKey()
	if key == nil {
		return nil, errors.New("key is nil")
	}

	if strings.HasPrefix(key.GetSourceName(), "http-client") ||
		strings.HasPrefix(key.GetDestName(), "http-client") {
		w.Log.Info("HTTP traffic detected",
			"src", key.GetSourceName(),
			"dest", key.GetDestName(),
			"dest_port", key.GetDestPort(),
			"proto", key.GetProto(),
			"reporter", key.GetReporter(),
		)
	}

	if key.GetAction() != pb.Action_Deny {
		return nil, nil //nolint:nilnil // This is not a policy deny event, just skip it
	}

	var egressPolicies, ingressPolicies []types.Policy
	policies := key.GetPolicies()
	if policies == nil {
		w.Log.Warn("policies in the flow is nil")
	} else {
		enforcedPolicies := policies.GetEnforcedPolicies()
		for _, policy := range enforcedPolicies {
			policyKind := policy.GetKind()
			policyName := policy.GetName()
			policyNamespace := policy.GetNamespace()
			policyTrigger := policy.GetTrigger()

			if policyName == "" && policyTrigger != nil {
				policyKind = policyTrigger.GetKind()
				policyName = policyTrigger.GetName()
				policyNamespace = policyTrigger.GetNamespace()
			}

			apiVersion, err := w.GetNetworkPolicyAPIVersion(policyKind.String())
			if err != nil {
				w.Log.Error("Failed to get API version for policy",
					"policyKind", policyKind.String(),
					"policyName", policyName,
					"policyNamespace", policyNamespace,
					"err", err)
				continue
			}
			p := types.Policy{
				TypeMeta:  metav1.TypeMeta{APIVersion: apiVersion, Kind: policyKind.String()},
				Name:      policyName,
				Namespace: policyNamespace,
			}

			switch key.GetReporter() {
			case pb.Reporter_Src:
				egressPolicies = append(egressPolicies, p)
			case pb.Reporter_Dst:
				ingressPolicies = append(ingressPolicies, p)
			case pb.Reporter_ReporterUnspecified:
				// Only Src and Dst are relevant for policy enforcement here
				continue
			}
		}
	}

	event := &types.PolicyDenyEvent{
		Timestamp:         flow.GetStartTime(),
		CNIType:           string(types.CNITypeCalico),
		Protocol:          corev1.Protocol(key.GetProto()),
		SrcNamespace:      key.GetSourceNamespace(),
		SrcName:           key.GetSourceName(),
		SrcLabels:         flow.GetSourceLabels(),
		DstNamespace:      key.GetDestNamespace(),
		DstName:           key.GetDestName(),
		DstLabels:         flow.GetDestLabels(),
		DstPort:           int32(key.GetDestPort()), //nolint:gosec // port 0-65535 fits int32
		EgressEnforcedBy:  egressPolicies,
		IngressEnforcedBy: ingressPolicies,
	}

	return event, nil
}

func (w *CalicoWatcher) Shutdown() error {
	if w.conn != nil {
		return w.conn.Close()
	}

	return nil
}
