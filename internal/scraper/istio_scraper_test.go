package scraper

import (
	"context"
	"log/slog"
	"testing"
	"time"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/network-enforcer/internal/types"
	"github.com/rancher-sandbox/network-enforcer/internal/violationbuf"
	"github.com/stretchr/testify/require"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/embedded"
	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
)

type fakeOtelEventLogger struct {
	embedded.Logger

	emitted []otellog.Record
}

func (f *fakeOtelEventLogger) Enabled(context.Context, otellog.EnabledParameters) bool { return true }

func (f *fakeOtelEventLogger) Emit(_ context.Context, rec otellog.Record) {
	f.emitted = append(f.emitted, rec.Clone())
}

func testScraper(
	enqueue LearningEnqueueFunc,
	buffer *violationbuf.Buffer,
	logger otellog.Logger,
) *IstioScraper {
	return NewIstioScraper(IstioScraperConfig{
		ViolationBuffer:      buffer,
		EnqueueLearningEvent: enqueue,
		ViolationOtelLogger:  logger,
		Logger:               slog.New(slog.DiscardHandler),
	})
}

// otlpRequest wraps the given log records into an ExportLogsServiceRequest.
func otlpRequest(records ...*logspb.LogRecord) *collogspb.ExportLogsServiceRequest {
	return &collogspb.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{
			{
				ScopeLogs: []*logspb.ScopeLogs{
					{LogRecords: records},
				},
			},
		},
	}
}

func otlpRecord(attrs map[string]string, unixNano int64) *logspb.LogRecord {
	rec := &logspb.LogRecord{TimeUnixNano: uint64(unixNano)}
	for k, v := range attrs {
		rec.Attributes = append(rec.Attributes, &commonpb.KeyValue{
			Key: k,
			Value: &commonpb.AnyValue{
				Value: &commonpb.AnyValue_StringValue{StringValue: v},
			},
		})
	}
	return rec
}

func TestExportRoutesRecordsByEventType(t *testing.T) {
	t.Parallel()

	unixNano := time.Date(2026, 8, 3, 15, 39, 7, 0, time.UTC).UnixNano()
	wantTimestamp := time.Unix(0, unixNano)

	cases := []struct {
		name string
		// attrs is the single OTLP record exported in this case.
		attrs map[string]string
		// wantLearned is the learning event expected in the learning pipeline,
		// or nil when the record must not be routed there.
		wantLearned *types.LearningEvent
		// wantRecord is the violation buffer record expected, or nil when the
		// record must not reach the buffer.
		wantRecord *violationbuf.ViolationRecord
		// wantOtel is the number of policy_violation_observed OTel logs emitted.
		wantOtel int
	}{
		{
			name: "learn routed to learning pipeline",
			attrs: map[string]string{
				eventTypeKey:    eventTypeLearn,
				dstNameKey:      "http-server-7bbf596dd9-4rgdc",
				dstNamespaceKey: "default",
				dstPortKey:      "18080",
				srcIdentityKey:  "spiffe://cluster.local/ns/default/sa/http-client-sa",
			},
			wantLearned: &types.LearningEvent{
				DstName:      "http-server-7bbf596dd9-4rgdc",
				DstNamespace: "default",
				DstPort:      "18080",
				// the `spiffe://` scheme is stripped on ingest.
				SrcIdentity: "cluster.local/ns/default/sa/http-client-sa",
			},
		},
		{
			name: "monitor dry-run DENY routed to violation buffer",
			attrs: map[string]string{
				eventTypeKey:         eventTypeMonitor,
				dstNamespacedNameKey: "default/http-server-7bbf596dd9-8gs65",
				policyKey:            "default/deny-http-server-monitor",
				srcAddrKey:           "10.244.0.9:46266",
			},
			wantRecord: &violationbuf.ViolationRecord{
				Timestamp:              wantTimestamp,
				Direction:              networkingv1.PolicyTypeIngress,
				SrcName:                "10.244.0.9:46266",
				DstNamespace:           "default",
				DstName:                "http-server-7bbf596dd9-8gs65",
				Protocol:               corev1.ProtocolTCP,
				Action:                 securityv1alpha1.WorkloadNetworkPolicyModeMonitor,
				DenyingPolicyNamespace: "default",
				DenyingPolicyName:      "deny-http-server-monitor",
			},
			wantOtel: 1,
		},
		{
			name: "violation explicit DENY routed to violation buffer",
			attrs: map[string]string{
				eventTypeKey:         eventTypeViolation,
				dstNamespacedNameKey: "default/http-server-6cbcc86f5d-lhq82",
				policyKey:            "default/deny-http-server-protect",
				srcAddrKey:           "10.244.0.5:49084",
			},
			wantRecord: &violationbuf.ViolationRecord{
				Timestamp:              wantTimestamp,
				Direction:              networkingv1.PolicyTypeIngress,
				SrcName:                "10.244.0.5:49084",
				DstNamespace:           "default",
				DstName:                "http-server-6cbcc86f5d-lhq82",
				Protocol:               corev1.ProtocolTCP,
				Action:                 securityv1alpha1.WorkloadNetworkPolicyModeProtect,
				DenyingPolicyNamespace: "default",
				DenyingPolicyName:      "deny-http-server-protect",
			},
			wantOtel: 1,
		},
		{
			name: "violation ALLOW-miss routed to violation buffer without policy",
			attrs: map[string]string{
				eventTypeKey:         eventTypeViolation,
				dstNamespacedNameKey: "default/http-server-6cbcc86f5d-lhq82",
				srcAddrKey:           "10.244.0.5:52814",
			},
			wantRecord: &violationbuf.ViolationRecord{
				Timestamp:    wantTimestamp,
				Direction:    networkingv1.PolicyTypeIngress,
				SrcName:      "10.244.0.5:52814",
				DstNamespace: "default",
				DstName:      "http-server-6cbcc86f5d-lhq82",
				Protocol:     corev1.ProtocolTCP,
				Action:       securityv1alpha1.WorkloadNetworkPolicyModeProtect,
			},
			wantOtel: 1,
		},
		{
			name: "unknown event type is skipped",
			attrs: map[string]string{
				eventTypeKey: "something-else",
				dstNameKey:   "http-server",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			learned := make([]types.LearningEvent, 0)
			buffer := violationbuf.NewBuffer()
			otelLogger := &fakeOtelEventLogger{}

			scraper := testScraper(
				func(ev types.LearningEvent) bool {
					learned = append(learned, ev)
					return true
				},
				buffer,
				otelLogger,
			)

			_, err := scraper.Export(context.Background(), otlpRequest(otlpRecord(tc.attrs, unixNano)))
			require.NoError(t, err)

			if tc.wantLearned != nil {
				require.Equal(t, []types.LearningEvent{*tc.wantLearned}, learned)
			} else {
				require.Empty(t, learned)
			}

			drained := buffer.Drain()
			if tc.wantRecord != nil {
				require.Equal(t, []violationbuf.ViolationRecord{*tc.wantRecord}, drained)
			} else {
				require.Empty(t, drained)
			}

			require.Len(t, otelLogger.emitted, tc.wantOtel)
		})
	}
}

func TestPolicyEventToObservation(t *testing.T) {
	t.Parallel()

	unixNano := time.Date(2026, 8, 3, 15, 39, 7, 0, time.UTC).UnixNano()

	attrs := map[string]string{
		eventTypeKey:         eventTypeViolation,
		dstNamespacedNameKey: "default/http-server-6cbcc86f5d-lhq82",
		policyKey:            "default/deny-http-server-protect",
		srcAddrKey:           "10.244.0.5:49084",
	}
	obs := policyEventToObservation(otlpRecord(attrs, unixNano), attrs)

	require.Equal(t, unixNano, obs.Timestamp.UnixNano())
	require.Equal(t, "10.244.0.5:49084", obs.Source.OwnerName)
	require.Equal(t, "default", obs.Dest.Namespace)
	require.Equal(t, "http-server-6cbcc86f5d-lhq82", obs.Dest.OwnerName)
	require.Equal(t, corev1.ProtocolTCP, obs.Protocol)
	require.Equal(t, securityv1alpha1.WorkloadNetworkPolicyModeProtect, obs.Action)
	require.Equal(t, "default", obs.DenyingPolicyNamespace)
	require.Equal(t, "deny-http-server-protect", obs.DenyingPolicyName)
}
