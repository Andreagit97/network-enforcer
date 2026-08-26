package scraper

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPortToInt32(t *testing.T) {
	t.Parallel()

	t.Run("uint32", func(t *testing.T) {
		t.Parallel()

		cases := []struct {
			name    string
			port    uint32
			want    int32
			wantErr bool
		}{
			{name: "zero", port: 0, want: 0},
			{name: "valid port", port: 8080, want: 8080},
			{name: "max port", port: 65535, want: 65535},
			{name: "max int32", port: math.MaxInt32, want: math.MaxInt32},
			{name: "above max int32", port: math.MaxInt32 + 1, wantErr: true},
			{name: "max uint32", port: math.MaxUint32, wantErr: true},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				got, err := portToInt32(tc.port)
				if tc.wantErr {
					require.ErrorIs(t, err, errPortOutOfRange)
					require.Zero(t, got)
					return
				}
				require.NoError(t, err)
				require.Equal(t, tc.want, got)
			})
		}
	})

	t.Run("int64", func(t *testing.T) {
		t.Parallel()

		cases := []struct {
			name    string
			port    int64
			want    int32
			wantErr bool
		}{
			{name: "zero", port: 0, want: 0},
			{name: "valid port", port: 8080, want: 8080},
			{name: "max int32", port: math.MaxInt32, want: math.MaxInt32},
			{name: "above max int32", port: math.MaxInt32 + 1, wantErr: true},
			{name: "negative", port: -1, wantErr: true},
			{name: "min int64", port: math.MinInt64, wantErr: true},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				got, err := portToInt32(tc.port)
				if tc.wantErr {
					require.ErrorIs(t, err, errPortOutOfRange)
					require.Zero(t, got)
					return
				}
				require.NoError(t, err)
				require.Equal(t, tc.want, got)
			})
		}
	})
}

func TestParsePort(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name           string
		port           string
		want           int32
		wantOutOfRange bool
		wantErr        bool
	}{
		{name: "min valid port", port: "1", want: minValidPort},
		{name: "valid port", port: "18080", want: 18080},
		{name: "max valid port", port: "65535", want: maxValidPort},
		{name: "zero is out of range", port: "0", wantErr: true, wantOutOfRange: true},
		{name: "negative is out of range", port: "-1", wantErr: true, wantOutOfRange: true},
		{name: "above max valid port", port: "65536", wantErr: true, wantOutOfRange: true},
		{name: "above max int32", port: "2147483648", wantErr: true},
		{name: "non numeric", port: "http", wantErr: true},
		{name: "empty", port: "", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := parsePort(tc.port)
			if tc.wantErr {
				require.Error(t, err)
				require.Zero(t, got)
				if tc.wantOutOfRange {
					require.ErrorIs(t, err, errPortOutOfRange)
				} else {
					require.NotErrorIs(t, err, errPortOutOfRange)
				}
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}
