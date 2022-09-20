package traceroute

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestExtractMessage(t *testing.T) {
	asHex := "4500003800000000f50178ac81fa08aec0a801c80b0077bd000000004500001d1a1740000111dd16c0a801c8cc86f3abaab8829b00094fe5"
	payload, err := hex.DecodeString(asHex)
	require.NoError(t, err, "hex decode error")
	now := time.Now().UTC()
	msg, err := extractMessage(payload, now)
	require.NoError(t, err, "extractMessage error")
	fmt.Println("MSG", msg.String())
}
