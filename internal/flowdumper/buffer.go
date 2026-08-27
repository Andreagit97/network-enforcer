package flowdumper

import (
	"encoding/json"
	"fmt"
	"sync"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const FieldName = "flow_debug"

type Buffer struct {
	mtx sync.Mutex
	buf []json.RawMessage
	pos int
}

func NewBuffer(capacity int) *Buffer {
	if capacity < 1 {
		capacity = 1
	}
	return &Buffer{buf: make([]json.RawMessage, capacity)}
}

func (b *Buffer) RecordAny(flow any) (bool, error) {
	raw, err := marshalFlow(flow)
	if err != nil {
		return false, err
	}
	b.mtx.Lock()
	defer b.mtx.Unlock()

	dropped := b.pos >= len(b.buf)
	b.buf[b.pos%len(b.buf)] = append(json.RawMessage(nil), raw...)
	b.pos++

	return dropped, nil
}

func (b *Buffer) Drain() []json.RawMessage {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	n := min(b.pos, len(b.buf))
	if n == 0 {
		return nil
	}

	start := 0
	if b.pos > len(b.buf) {
		start = b.pos % len(b.buf)
	}

	records := make([]json.RawMessage, 0, n)
	for i := range n {
		idx := (start + i) % len(b.buf)
		records = append(records, append(json.RawMessage(nil), b.buf[idx]...))
	}

	b.pos = 0
	return records
}

func marshalFlow(flow any) (json.RawMessage, error) {
	if msg, ok := flow.(proto.Message); ok {
		raw, err := protojson.Marshal(msg)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal proto flow: %w", err)
		}
		return raw, nil
	}

	raw, err := json.Marshal(flow)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal flow: %w", err)
	}
	return raw, nil
}
