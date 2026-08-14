package violation

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
)

func TestBufferRecordAndDrain(t *testing.T) {
	buf := NewBuffer()

	buf.Record(ViolationRecord{
		Direction:              networkingv1.PolicyTypeEgress,
		SrcNamespace:           "ns1",
		SrcName:                "pod1",
		DstNamespace:           "ns2",
		DstName:                "svc1",
		Protocol:               corev1.ProtocolTCP,
		DstPort:                80,
		Action:                 "protect",
		DenyingPolicyName:      "deny-all",
		DenyingPolicyNamespace: "ns1",
	})

	records := buf.Drain()
	require.Len(t, records, 1)
	require.Equal(t, networkingv1.PolicyTypeEgress, records[0].Direction)
	require.Equal(t, "deny-all", records[0].DenyingPolicyName)
	require.Equal(t, int32(80), records[0].DstPort)

	// After drain, buffer should be empty.
	records = buf.Drain()
	require.Empty(t, records)
}

func TestBufferOverwritesOldest(t *testing.T) {
	buf := NewBuffer()

	// Fill the buffer to capacity.
	for i := range MaxBufferEntries {
		dropped := buf.Record(ViolationRecord{
			SrcName:   fmt.Sprintf("pod-%d", i),
			Action:    "protect",
			Direction: networkingv1.PolicyTypeEgress,
			DstPort:   int32(i),
		})
		require.False(t, dropped, "should not drop while filling buffer")
	}

	// Add one more — should overwrite the oldest (pod-0).
	dropped := buf.Record(ViolationRecord{
		SrcName:   "pod-overflow",
		Action:    "protect",
		Direction: networkingv1.PolicyTypeEgress,
		DstPort:   9999,
	})
	require.True(t, dropped, "should report a drop when buffer overflows")

	records := buf.Drain()
	require.Len(t, records, MaxBufferEntries)

	// Newest should be pod-overflow (first in newest-to-oldest order).
	require.Equal(t, "pod-overflow", records[0].SrcName)
	// Oldest should now be pod-1 (pod-0 was overwritten).
	require.Equal(t, "pod-1", records[len(records)-1].SrcName)
}

func TestBufferDrainReverseChronologicalOrder(t *testing.T) {
	buf := NewBuffer()

	baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range 5 {
		buf.Record(ViolationRecord{
			Timestamp: baseTime.Add(time.Duration(i) * time.Second),
			SrcName:   fmt.Sprintf("pod-%d", i),
			Action:    "protect",
			Direction: networkingv1.PolicyTypeEgress,
		})
	}

	records := buf.Drain()
	require.Len(t, records, 5)
	for i, rec := range records {
		require.Equal(t, fmt.Sprintf("pod-%d", 4-i), rec.SrcName)
	}
}

func TestBufferDrainAfterOverflow(t *testing.T) {
	buf := NewBuffer()

	totalRecords := MaxBufferEntries + 50

	for i := range totalRecords {
		buf.Record(ViolationRecord{
			SrcName:   fmt.Sprintf("pod-%d", i),
			Action:    "protect",
			Direction: networkingv1.PolicyTypeEgress,
		})
	}

	records := buf.Drain()
	require.Len(t, records, MaxBufferEntries)

	// The oldest 50 entries (pod-0 through pod-49) were overwritten.
	// Records should be in reverse chronological order: pod-(totalRecords-1), ..., pod-50.
	for i, rec := range records {
		expected := fmt.Sprintf("pod-%d", totalRecords-1-i)
		require.Equal(
			t,
			expected,
			rec.SrcName,
			"record at index %d should be %s, got %s",
			i,
			expected,
			rec.SrcName,
		)
	}
}

func TestConcurrentRecordAndDrain(_ *testing.T) {
	buf := NewBuffer()

	done := make(chan struct{})

	// Concurrently record.
	go func() {
		for i := range 1000 {
			buf.Record(ViolationRecord{
				SrcName:   fmt.Sprintf("pod-%d", i),
				Action:    "protect",
				Direction: networkingv1.PolicyTypeEgress,
			})
		}
		close(done)
	}()

	// Concurrently drain (may see partial data, should not race).
	for range 10 {
		_ = buf.Drain()
	}

	<-done
	// Final drain should not panic.
	_ = buf.Drain()
}
