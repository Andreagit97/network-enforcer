package cniwatcher

import (
	"log/slog"
	"os"
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	hubbleObserver "github.com/cilium/cilium/api/v1/observer"
	monitorApi "github.com/cilium/cilium/pkg/monitor/api"
	pb "github.com/rancher-sandbox/network-enforcer/internal/cniwatcher/calico/goldmane"
	"github.com/rancher-sandbox/network-enforcer/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestCalicoParsePolicyDenyEvent_DstPort(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	w := &CalicoWatcher{
		Watcher: Watcher{Log: logger},
	}

	tests := []struct {
		name     string
		flow     *pb.FlowResult
		wantPort int32
		wantErr  bool
	}{
		{
			name: "TCP flow with destination port 443",
			flow: &pb.FlowResult{
				Flow: &pb.Flow{
					Key: &pb.FlowKey{
						Action:   pb.Action_Deny,
						Proto:    "TCP",
						DestPort: 443,
					},
				},
			},
			wantPort: 443,
			wantErr:  false,
		},
		{
			name: "TCP flow with destination port 80",
			flow: &pb.FlowResult{
				Flow: &pb.Flow{
					Key: &pb.FlowKey{
						Action:   pb.Action_Deny,
						Proto:    "TCP",
						DestPort: 80,
					},
				},
			},
			wantPort: 80,
			wantErr:  false,
		},
		{
			name: "Non-deny action returns nil (skipped)",
			flow: &pb.FlowResult{
				Flow: &pb.Flow{
					Key: &pb.FlowKey{
						Action: pb.Action_Allow,
					},
				},
			},
			wantPort: 0,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := w.parsePolicyDenyEvent(tt.flow)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			if event == nil {
				// Non-deny events are skipped
				assert.Equal(t, pb.Action_Allow, tt.flow.GetFlow().GetKey().GetAction())
				return
			}
			assert.Equal(t, tt.wantPort, event.DstPort)
		})
	}
}

func TestCiliumParsePolicyDenyEvent_DstPort(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	w := &CiliumWatcher{
		Watcher: Watcher{Log: logger},
	}

	tests := []struct {
		name         string
		flow         *hubbleObserver.GetFlowsResponse
		wantPort     int32
		wantProtocol corev1.Protocol
		wantErr      bool
	}{
		{
			name: "TCP flow with destination port 443",
			flow: &hubbleObserver.GetFlowsResponse{
				ResponseTypes: &hubbleObserver.GetFlowsResponse_Flow{
					Flow: &flowpb.Flow{
						EventType: &flowpb.CiliumEventType{
							Type: monitorApi.MessageTypePolicyVerdict,
						},
						DropReasonDesc: flowpb.DropReason_POLICY_DENIED,
						L4: &flowpb.Layer4{
							Protocol: &flowpb.Layer4_TCP{
								TCP: &flowpb.TCP{
									DestinationPort: 443,
								},
							},
						},
					},
				},
			},
			wantPort:     443,
			wantProtocol: corev1.ProtocolTCP,
			wantErr:      false,
		},
		{
			name: "UDP flow with destination port 53",
			flow: &hubbleObserver.GetFlowsResponse{
				ResponseTypes: &hubbleObserver.GetFlowsResponse_Flow{
					Flow: &flowpb.Flow{
						EventType: &flowpb.CiliumEventType{
							Type: monitorApi.MessageTypePolicyVerdict,
						},
						DropReasonDesc: flowpb.DropReason_POLICY_DENIED,
						L4: &flowpb.Layer4{
							Protocol: &flowpb.Layer4_UDP{
								UDP: &flowpb.UDP{
									DestinationPort: 53,
								},
							},
						},
					},
				},
			},
			wantPort:     53,
			wantProtocol: corev1.ProtocolUDP,
			wantErr:      false,
		},
		{
			name: "unsupported L4 protocol has no port (0)",
			flow: &hubbleObserver.GetFlowsResponse{
				ResponseTypes: &hubbleObserver.GetFlowsResponse_Flow{
					Flow: &flowpb.Flow{
						EventType: &flowpb.CiliumEventType{
							Type: monitorApi.MessageTypePolicyVerdict,
						},
						DropReasonDesc: flowpb.DropReason_POLICY_DENIED,
						L4: &flowpb.Layer4{
							Protocol: &flowpb.Layer4_ICMPv4{
								ICMPv4: &flowpb.ICMPv4{},
							},
						},
					},
				},
			},
			wantPort:     0,
			wantProtocol: corev1.Protocol(types.ProtocolUnknown),
			wantErr:      false,
		},
		{
			name: "TCP flow with drop reason POLICY_DENY treated as deny",
			flow: &hubbleObserver.GetFlowsResponse{
				ResponseTypes: &hubbleObserver.GetFlowsResponse_Flow{
					Flow: &flowpb.Flow{
						EventType: &flowpb.CiliumEventType{
							Type: monitorApi.MessageTypePolicyVerdict,
						},
						DropReasonDesc: flowpb.DropReason_POLICY_DENY,
						L4: &flowpb.Layer4{
							Protocol: &flowpb.Layer4_TCP{
								TCP: &flowpb.TCP{
									DestinationPort: 8080,
								},
							},
						},
					},
				},
			},
			wantPort:     8080,
			wantProtocol: corev1.ProtocolTCP,
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := w.parsePolicyDenyEvent(tt.flow)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NotNil(t, event, "expected a PolicyDenyEvent, got nil")
			assert.Equal(t, tt.wantPort, event.DstPort)
			assert.Equal(t, tt.wantProtocol, event.Protocol)
		})
	}
}

func TestAWSVPCParsePolicyDenyEvent_DstPortZero(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	fakeClient := fake.NewClientBuilder().Build()
	w := &AWSVPCWatcher{
		Watcher: Watcher{Log: logger, Ctx: t.Context(), Client: fakeClient},
	}

	// AWSVPC deny logs don't carry destination port, so DstPort should be 0.
	logLine := `{"level":"info","ts":"2025-06-01T12:00:00Z","logger":"network-policy-agent","msg":"","Src IP":"10.0.0.1","Src Port":12345,"Dest IP":"10.0.0.2","Dest Port":80,"Proto":"TCP","Verdict":"DENY"}`
	event, err := w.parsePolicyDenyEvent(logLine)
	require.NoError(t, err)
	require.NotNil(t, event)
	assert.Equal(t, int32(0), event.DstPort, "AWSVPC should leave DstPort as 0")
}

func TestFlannelParsePolicyDenyEvent_DstPortZero(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	fakeClient := fake.NewClientBuilder().Build()
	w := &FlannelWatcher{
		Watcher: Watcher{Log: logger, Ctx: t.Context(), Client: fakeClient},
	}

	// Flannel deny logs don't reliably carry destination port, leave DstPort as 0.
	line := "Jan 15 14:30:25 node1 DROP by policy default/deny-all IN=eth0 " +
		"OUT=eth1 MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd SRC=10.244.1.5 " +
		"DST=10.244.2.10 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP " +
		"SPT=45678 DPT=80 WINDOW=29200 RES=0x00 SYN URGP=0"
	event := w.parsePolicyDenyEvent(line)
	require.NotNil(t, event)
	// Flannel's DstPort is explicitly left as 0 per spec (even though the log captures DPT).
	assert.Equal(t, int32(0), event.DstPort, "Flannel should leave DstPort as 0")
}
