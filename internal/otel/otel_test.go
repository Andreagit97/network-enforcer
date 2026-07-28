package otel_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rancher-sandbox/network-enforcer/internal/otel"
	"github.com/rancher-sandbox/network-enforcer/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/logtest"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestOtelService_Start(t *testing.T) {
	ctx := t.Context()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg := otel.OpenTelemetryConfig{
		Ctx:               ctx,
		Log:               logger,
		CollectorEndpoint: "localhost:4317",
	}
	service := otel.NewOpenTelemetryService(cfg)

	err := service.Start()
	if err != nil {
		t.Logf("Expected error in test environment: %v", err)
	} else {
		t.Logf("OpenTelemetry started successfully in test environment")
	}
}

func TestOtelService_EmitPolicyDenyEvent(t *testing.T) {
	ctx := t.Context()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ts := time.Unix(1700000000, 0)

	tests := []struct {
		name           string
		initLogger     bool
		event          *types.PolicyDenyEvent
		wantErr        bool
		wantAttributes []otellog.KeyValue
	}{
		{
			name: "uninitialized",
			event: &types.PolicyDenyEvent{
				Timestamp:    ts.Unix(),
				NodeName:     "test-node",
				CNIType:      "test-cni",
				Protocol:     "TCP",
				SrcNamespace: "default",
				SrcName:      "test-pod",
				DstNamespace: "default",
				DstName:      "test-service",
			},
			wantErr: true,
		},
		{
			name:       "emits full record",
			initLogger: true,
			event: &types.PolicyDenyEvent{
				Timestamp:    ts.Unix(),
				NodeName:     "node-1",
				CNIType:      "cilium",
				Protocol:     "TCP",
				SrcNamespace: "src-ns",
				SrcName:      "src-pod",
				SrcLabels:    []string{"app=frontend"},
				SrcWorkloads: []string{"Deployment/frontend"},
				DstNamespace: "dst-ns",
				DstName:      "dst-pod",
				DstLabels:    []string{"app=backend"},
				DstWorkloads: []string{"Deployment/backend"},
				DstPort:      8080,
				EgressEnforcedBy: []types.Policy{{
					TypeMeta:  metav1.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"},
					Name:      "deny-egress",
					Namespace: "src-ns",
				}},
				IngressEnforcedBy: []types.Policy{{
					TypeMeta:  metav1.TypeMeta{APIVersion: "cilium.io/v2", Kind: "CiliumNetworkPolicy"},
					Name:      "deny-ingress",
					Namespace: "dst-ns",
				}},
			},
			wantAttributes: []otellog.KeyValue{
				otellog.String("cni.type", "cilium"),
				otellog.String("network.protocol", "TCP"),
				otellog.String("node.name", "node-1"),
				otellog.String("source.namespace", "src-ns"),
				otellog.String("source.name", "src-pod"),
				otellog.Slice("source.labels", otellog.StringValue("app=frontend")),
				otellog.Slice("source.workloads", otellog.StringValue("Deployment/frontend")),
				otellog.String("destination.namespace", "dst-ns"),
				otellog.String("destination.name", "dst-pod"),
				otellog.Slice("destination.labels", otellog.StringValue("app=backend")),
				otellog.Slice("destination.workloads", otellog.StringValue("Deployment/backend")),
				otellog.Int64("destination.port", 8080),
				otellog.Slice("egress.enforced_by",
					otellog.StringValue("networking.k8s.io/v1/NetworkPolicy/src-ns/deny-egress")),
				otellog.Slice("ingress.enforced_by",
					otellog.StringValue("cilium.io/v2/CiliumNetworkPolicy/dst-ns/deny-ingress")),
			},
		},
		{
			name:       "omits empty optional attrs",
			initLogger: true,
			event: &types.PolicyDenyEvent{
				Timestamp:    ts.Unix(),
				NodeName:     "node-1",
				CNIType:      "flannel",
				Protocol:     "ICMP",
				SrcNamespace: "src-ns",
				SrcName:      "src-pod",
				DstNamespace: "dst-ns",
				DstName:      "dst-pod",
			},
			wantAttributes: []otellog.KeyValue{
				otellog.String("cni.type", "flannel"),
				otellog.String("network.protocol", "ICMP"),
				otellog.String("node.name", "node-1"),
				otellog.String("source.namespace", "src-ns"),
				otellog.String("source.name", "src-pod"),
				otellog.String("destination.namespace", "dst-ns"),
				otellog.String("destination.name", "dst-pod"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := otel.NewOpenTelemetryService(otel.OpenTelemetryConfig{
				Ctx:               ctx,
				Log:               logger,
				CollectorEndpoint: "localhost:4317",
			})

			var recorder *logtest.Recorder
			if tt.initLogger {
				recorder = logtest.NewRecorder()
				service.Service.Logger = recorder.Logger("cniwatcher")
			}

			err := service.EmitPolicyDenyEvent(tt.event)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			want := logtest.Recording{
				logtest.Scope{Name: "cniwatcher"}: {
					{
						Context:    ctx,
						EventName:  "policy_deny",
						Timestamp:  ts,
						Severity:   otellog.SeverityWarn,
						Body:       otellog.StringValue("Network policy denied traffic"),
						Attributes: tt.wantAttributes,
					},
				},
			}
			logtest.AssertEqual(t, want, recorder.Result())
		})
	}
}

func TestOtelService_Shutdown(t *testing.T) {
	ctx := t.Context()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg := otel.OpenTelemetryConfig{
		Ctx:               ctx,
		Log:               logger,
		CollectorEndpoint: "localhost:4317",
	}
	service := otel.NewOpenTelemetryService(cfg)

	err := service.Shutdown(ctx)
	assert.NoError(t, err)
}

func generateCACertPEM(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func generateClientKeyPair(t *testing.T, dir string) (string, string) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{Organization: []string{"Test CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{Organization: []string{"Test Client"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	writeCertFile(t, certPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))

	keyBytes, err := x509.MarshalECPrivateKey(leafKey)
	require.NoError(t, err)
	writeCertFile(t, keyPath,
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}))

	return certPath, keyPath
}

func writeCertFile(t *testing.T, path string, data []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, data, 0o600))
}

func TestStart_RejectsUnsupportedProtocol(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	svc := otel.NewOpenTelemetryService(otel.OpenTelemetryConfig{
		Ctx:               t.Context(),
		Log:               logger,
		CollectorEndpoint: "localhost:4317",
		Protocol:          "smoke-signals",
	})
	err := svc.Start()
	require.Error(t, err, "expected error for unsupported protocol")
	require.Contains(t, err.Error(), "unsupported protocol")
}

func TestStart_GRPCInsecure(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	svc := otel.NewOpenTelemetryService(otel.OpenTelemetryConfig{
		Ctx:               t.Context(),
		Log:               logger,
		CollectorEndpoint: "localhost:4317",
		Protocol:          "grpc",
	})
	require.NoError(t, svc.Start())
	require.NoError(t, svc.Shutdown(t.Context()))
}

func TestStart_GRPCDefaultsToGRPCWhenProtocolEmpty(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	svc := otel.NewOpenTelemetryService(otel.OpenTelemetryConfig{
		Ctx:               t.Context(),
		Log:               logger,
		CollectorEndpoint: "localhost:4317",
	})
	require.NoError(t, svc.Start())
	require.NoError(t, svc.Shutdown(t.Context()))
}

func TestStart_GRPCmTLS(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	writeCertFile(t, caPath, generateCACertPEM(t))
	certPath, keyPath := generateClientKeyPair(t, dir)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	svc := otel.NewOpenTelemetryService(otel.OpenTelemetryConfig{
		Ctx:               t.Context(),
		Log:               logger,
		CollectorEndpoint: "otel-collector:4317",
		Protocol:          "grpc",
		CACert:            caPath,
		ClientCert:        certPath,
		ClientKey:         keyPath,
	})
	require.NoError(t, svc.Start())
	require.NoError(t, svc.Shutdown(t.Context()))
}

func TestStart_GRPCmTLSMissingCA(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	svc := otel.NewOpenTelemetryService(otel.OpenTelemetryConfig{
		Ctx:               t.Context(),
		Log:               logger,
		CollectorEndpoint: "otel-collector:4317",
		Protocol:          "grpc",
		CACert:            filepath.Join(t.TempDir(), "missing-ca.crt"),
	})
	require.Error(t, svc.Start())
}

func TestStart_RejectsClientCertWithoutCA(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	svc := otel.NewOpenTelemetryService(otel.OpenTelemetryConfig{
		Ctx:               t.Context(),
		Log:               logger,
		CollectorEndpoint: "localhost:4317",
		Protocol:          "grpc",
		ClientCert:        "/some/cert.pem",
		ClientKey:         "/some/key.pem",
	})
	err := svc.Start()
	require.Error(t, err)
	require.Contains(t, err.Error(), "client certificate requires a CA certificate")
}

func TestStart_HTTPProtobufInsecure(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	svc := otel.NewOpenTelemetryService(otel.OpenTelemetryConfig{
		Ctx:               t.Context(),
		Log:               logger,
		CollectorEndpoint: "http://localhost:4318",
		Protocol:          "http/protobuf",
	})
	require.NoError(t, svc.Start())
	require.NoError(t, svc.Shutdown(t.Context()))
}

func TestStart_HTTPProtobufmTLS(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	writeCertFile(t, caPath, generateCACertPEM(t))
	certPath, keyPath := generateClientKeyPair(t, dir)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	svc := otel.NewOpenTelemetryService(otel.OpenTelemetryConfig{
		Ctx:               t.Context(),
		Log:               logger,
		CollectorEndpoint: "https://otel-collector:4318",
		Protocol:          "http/protobuf",
		CACert:            caPath,
		ClientCert:        certPath,
		ClientKey:         keyPath,
	})
	require.NoError(t, svc.Start())
	require.NoError(t, svc.Shutdown(t.Context()))
}
