//go:build !linux

package node

import (
	"context"
	"errors"
)

func discoverOpenPorts(_ context.Context, _ DiscoveryOptions, _ []uint16) (*openPortScanResult, error) {
	return nil, errors.New("raw parity discovery is only supported on linux")
}
