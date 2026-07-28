package otel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/rancher-sandbox/network-enforcer/internal/tlsutil"
	"github.com/rancher-sandbox/network-enforcer/internal/types"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.30.0"
	"google.golang.org/grpc/credentials"
)

type OpenTelemetryConfig struct {
	Ctx               context.Context
	Log               *slog.Logger
	CollectorEndpoint string
	// Protocol is the OTLP protocol: "grpc" or "http/protobuf".
	// Empty defaults to "grpc".
	Protocol string
	// CACert is the path to the CA certificate for verifying the collector's
	// TLS cert. Empty means insecure (plaintext).
	CACert string
	// ClientCert is the path to the client TLS certificate for mTLS.
	// Optional; requires CACert and ClientKey.
	ClientCert string
	// ClientKey is the path to the client TLS key for mTLS.
	// Optional; requires CACert and ClientCert.
	ClientKey string
}

type protocol string

const (
	protocolGRPC         protocol = "grpc"
	protocolHTTPProtobuf protocol = "http/protobuf"
)

func stringToProtocol(s string) (protocol, error) {
	if s == "" {
		return protocolGRPC, nil
	}
	switch s {
	case "grpc":
		return protocolGRPC, nil
	case "http/protobuf":
		return protocolHTTPProtobuf, nil
	default:
		return "", fmt.Errorf("unsupported protocol: %s", s)
	}
}

type OpenTelemetryService struct {
	LoggerProvider *sdklog.LoggerProvider
	Logger         otellog.Logger
}

type Service struct {
	Config  OpenTelemetryConfig
	Service *OpenTelemetryService
}

func NewOpenTelemetryService(cfg OpenTelemetryConfig) *Service {
	return &Service{
		Config:  cfg,
		Service: &OpenTelemetryService{},
	}
}

func (s *Service) Start() error {
	exporter, err := s.createExporter()
	if err != nil {
		return err
	}

	res, err := resource.New(s.Config.Ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String("cniwatcher"),
		),
	)
	if err != nil {
		return fmt.Errorf("failed to create resource: %w", err)
	}

	s.Service.LoggerProvider = sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
		sdklog.WithResource(res),
	)

	s.Service.Logger = s.Service.LoggerProvider.Logger("cniwatcher")
	s.Config.Log.Info("OpenTelemetry initialized",
		"collector", s.Config.CollectorEndpoint,
		"protocol", s.Config.Protocol,
		"insecure", s.Config.CACert == "")
	return nil
}

func (s *Service) createExporter() (sdklog.Exporter, error) {
	proto, err := stringToProtocol(s.Config.Protocol)
	if err != nil {
		return nil, err
	}

	// Reject client certs without a CA up front, mirroring events.Init.
	if s.Config.CACert == "" && (s.Config.ClientCert != "" || s.Config.ClientKey != "") {
		return nil, errors.New("client certificate requires a CA certificate (caCert is empty)")
	}

	switch proto {
	case protocolGRPC:
		return s.createGRPCExporter()
	case protocolHTTPProtobuf:
		return s.createHTTPExporter()
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", s.Config.Protocol)
	}
}

func (s *Service) createGRPCExporter() (sdklog.Exporter, error) {
	// Strip any http(s) prefix; WithEndpoint expects host:port.
	gRPCEndpoint := strings.TrimPrefix(strings.TrimPrefix(s.Config.CollectorEndpoint, "https://"), "http://")
	insecure := s.Config.CACert == ""
	opts := []otlploggrpc.Option{
		otlploggrpc.WithEndpoint(gRPCEndpoint),
	}
	if insecure {
		opts = append(opts, otlploggrpc.WithInsecure())
	} else {
		tlsConfig, err := tlsutil.ClientTLSConfig(s.Config.CACert, s.Config.ClientCert, s.Config.ClientKey)
		if err != nil {
			return nil, err
		}
		opts = append(opts, otlploggrpc.WithTLSCredentials(credentials.NewTLS(tlsConfig)))
	}
	return otlploggrpc.New(s.Config.Ctx, opts...)
}

func (s *Service) createHTTPExporter() (sdklog.Exporter, error) {
	// Strip any scheme prefix; WithEndpoint expects host:port.
	httpEndpoint := strings.TrimPrefix(strings.TrimPrefix(s.Config.CollectorEndpoint, "https://"), "http://")
	opts := []otlploghttp.Option{
		otlploghttp.WithEndpoint(httpEndpoint),
	}
	// Empty CA means insecure. An explicit http:// scheme also opts into insecure.
	if s.Config.CACert == "" || strings.HasPrefix(s.Config.CollectorEndpoint, "http://") {
		opts = append(opts, otlploghttp.WithInsecure())
	} else {
		tlsConfig, err := tlsutil.ClientTLSConfig(s.Config.CACert, s.Config.ClientCert, s.Config.ClientKey)
		if err != nil {
			return nil, err
		}
		opts = append(opts, otlploghttp.WithTLSClientConfig(tlsConfig))
	}
	return otlploghttp.New(s.Config.Ctx, opts...)
}

func policiesToStrings(policies []types.Policy) []string {
	if policies == nil {
		return nil
	}
	result := make([]string, len(policies))
	for i, p := range policies {
		result[i] = p.String()
	}
	return result
}

func stringSlice(key string, values []string) otellog.KeyValue {
	vals := make([]otellog.Value, len(values))
	for i, v := range values {
		vals[i] = otellog.StringValue(v)
	}
	return otellog.Slice(key, vals...)
}

func appendIfNotEmpty(attrs []otellog.KeyValue, key string, values []string) []otellog.KeyValue {
	if len(values) > 0 {
		return append(attrs, stringSlice(key, values))
	}
	return attrs
}

func (s *Service) EmitPolicyDenyEvent(event *types.PolicyDenyEvent) error {
	if s.Service.Logger == nil {
		return errors.New("OpenTelemetry is not initialized, skip emitting policy deny event")
	}

	s.Config.Log.Info("Emitting policy deny event", "event", event)

	var rec otellog.Record
	rec.SetEventName("policy_deny")
	rec.SetSeverity(otellog.SeverityWarn)
	rec.SetBody(otellog.StringValue("Network policy denied traffic"))
	ts := time.Unix(event.Timestamp, 0)
	rec.SetTimestamp(ts)

	attrs := []otellog.KeyValue{
		otellog.String("cni.type", event.CNIType),
		otellog.String("network.protocol", string(event.Protocol)),
		otellog.String("node.name", event.NodeName),
		otellog.String("source.namespace", event.SrcNamespace),
		otellog.String("source.name", event.SrcName),
		otellog.String("destination.namespace", event.DstNamespace),
		otellog.String("destination.name", event.DstName),
	}
	attrs = appendIfNotEmpty(attrs, "source.labels", event.SrcLabels)
	attrs = appendIfNotEmpty(attrs, "source.workloads", event.SrcWorkloads)
	attrs = appendIfNotEmpty(attrs, "destination.labels", event.DstLabels)
	attrs = appendIfNotEmpty(attrs, "destination.workloads", event.DstWorkloads)
	if event.DstPort != 0 {
		attrs = append(attrs, otellog.Int64("destination.port", int64(event.DstPort)))
	}
	attrs = appendIfNotEmpty(attrs, "egress.enforced_by", policiesToStrings(event.EgressEnforcedBy))
	attrs = appendIfNotEmpty(attrs, "ingress.enforced_by", policiesToStrings(event.IngressEnforcedBy))
	rec.AddAttributes(attrs...)

	s.Service.Logger.Emit(s.Config.Ctx, rec)
	return nil
}

func (s *Service) Shutdown(ctx context.Context) error {
	if s.Service.LoggerProvider == nil {
		return nil
	}

	return s.Service.LoggerProvider.Shutdown(ctx)
}
