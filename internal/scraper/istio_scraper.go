package scraper

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/rancher-sandbox/network-enforcer/internal/types"
	"github.com/rancher-sandbox/network-enforcer/internal/violationbuf"
	otellog "go.opentelemetry.io/otel/log"
	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/grpc"
)

const gracefulGRPCTimeout = 5 * time.Second

type OTLPConf struct {
	Port int
}

type LearningEnqueueFunc func(types.LearningEvent) bool

const (
	// keys.
	eventTypeKey         = "evt.type"
	srcIdentityKey       = "src.identity"
	dstNamespaceKey      = "dst.namespace"
	dstNameKey           = "dst.name"
	dstPortKey           = "dst.port"
	bodyKey              = "body"
	policyKey            = "policy"
	dstNamespacedNameKey = "dst.namespaced_name"
	srcAddrKey           = "src.addr"

	eventTypeLearn   = "learn"
	eventTypeMonitor = "monitor"

	spiffeURIPrefix = "spiffe://"
)

// IstioScraperConfig configures IstioScraper.
type IstioScraperConfig struct {
	ViolationBuffer      *violationbuf.Buffer
	EnqueueLearningEvent LearningEnqueueFunc
	Logger               *slog.Logger
	ViolationOtelLogger  otellog.Logger
	OTLPConf             OTLPConf
}

// IstioScraper receives OTLP log events from istio-watchers.
type IstioScraper struct {
	collogspb.UnimplementedLogsServiceServer
	IstioScraperConfig
}

// NewIstioScraper creates an OTLP log scraper for Istio.
func NewIstioScraper(
	conf IstioScraperConfig,
) *IstioScraper {
	return &IstioScraper{
		IstioScraperConfig: conf,
	}
}

func (s *IstioScraper) Start(ctx context.Context) error {
	defer func() {
		s.Logger.InfoContext(ctx, "istio scraper has stopped")
	}()
	lc := net.ListenConfig{}
	addr := fmt.Sprintf(":%d", s.OTLPConf.Port)
	listener, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	var opts []grpc.ServerOption
	s.Logger.InfoContext(ctx, "OTLP Istio scraper running in insecure mode")

	grpcServer := grpc.NewServer(opts...)
	collogspb.RegisterLogsServiceServer(grpcServer, s)
	s.Logger.InfoContext(ctx, "Starting OTLP logs server", "addr", addr)

	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- grpcServer.Serve(listener)
	}()

	select {
	case err = <-serveErrCh:
		if err != nil {
			return fmt.Errorf("gRPC server.Serve error: %w", err)
		}
		return nil

	case <-ctx.Done():
		done := make(chan struct{})
		go func() {
			grpcServer.GracefulStop()
			close(done)
		}()

		select {
		case <-done:
			// graceful stop completed
		case <-time.After(gracefulGRPCTimeout):
			s.Logger.WarnContext(ctx, "GracefulStop timed out; forcing Stop()", "timeout", gracefulGRPCTimeout.String())
			grpcServer.Stop()
		}

		// wait for Serve to return (usually immediate after Stop/GracefulStop)
		err = <-serveErrCh
		if err != nil {
			return fmt.Errorf("gRPC server.Serve error: %w", err)
		}
		return nil
	}
}

func (s *IstioScraper) Export(
	ctx context.Context,
	req *collogspb.ExportLogsServiceRequest,
) (*collogspb.ExportLogsServiceResponse, error) {
	// todo!: evaluate if this is the correct way to extract logs, this is AI-generated.
	for _, resourceLogs := range req.GetResourceLogs() {
		resourceAttrs := attrMap(resourceLogs.GetResource().GetAttributes())
		for _, scopeLogs := range resourceLogs.GetScopeLogs() {
			for _, record := range scopeLogs.GetLogRecords() {
				attrs := mergeAttrMaps(resourceAttrs, attrMap(record.GetAttributes()))
				s.Logger.InfoContext(ctx, "Received OTLP log record", "attrs", attrs)
				if attrs[eventTypeKey] != eventTypeLearn {
					// todo!: we need to handle other events, monitor/protect
					continue
				}
				dstName := attrs[dstNameKey]
				dstNamespace := attrs[dstNamespaceKey]
				dstPort := attrs[dstPortKey]
				srcIdentity, hasSPIFFEPrefix := strings.CutPrefix(attrs[srcIdentityKey], spiffeURIPrefix)
				if dstName == "" || dstNamespace == "" || dstPort == "" || !hasSPIFFEPrefix || srcIdentity == "" {
					s.Logger.WarnContext(ctx, "Skipping learning event with missing required fields",
						dstNameKey, dstName,
						dstNamespaceKey, dstNamespace,
						dstPortKey, dstPort,
						srcIdentityKey, attrs[srcIdentityKey],
						"attrs", attrs,
					)
					continue
				}
				if !s.EnqueueLearningEvent(types.LearningEvent{
					DstName:      dstName,
					DstNamespace: dstNamespace,
					DstPort:      dstPort,
					SrcIdentity:  srcIdentity,
				}) {
					// todo!: we can consider some rate limiting here
					s.Logger.WarnContext(ctx, "Failed to enqueue learning event, channel is full")
				}
			}
		}
	}

	return &collogspb.ExportLogsServiceResponse{}, nil
}

func mergeAttrMaps(base, override map[string]string) map[string]string {
	merged := make(map[string]string, len(base)+len(override))
	maps.Copy(merged, base)
	maps.Copy(merged, override)
	return merged
}

func attrMap(attrs []*commonpb.KeyValue) map[string]string {
	m := make(map[string]string, len(attrs))
	for _, kv := range attrs {
		value := anyValueToString(kv.GetValue())
		if value == "" {
			continue
		}
		m[kv.GetKey()] = value
	}
	return m
}

func anyValueToString(value *commonpb.AnyValue) string {
	if value == nil {
		return ""
	}

	switch v := value.GetValue().(type) {
	case *commonpb.AnyValue_StringValue:
		return v.StringValue
	case *commonpb.AnyValue_IntValue:
		return strconv.FormatInt(v.IntValue, 10)
	case *commonpb.AnyValue_DoubleValue:
		return strconv.FormatFloat(v.DoubleValue, 'f', -1, 64)
	case *commonpb.AnyValue_BoolValue:
		return strconv.FormatBool(v.BoolValue)
	default:
		return ""
	}
}
