package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// redactToken replaces the whole value with a stable, obvious token.
const redactToken = "[REDACTED]"

// maskValue applies one masking operation to a scalar value. Non-scalars are
// always fully redacted so masked output can never leak nested plaintext.
func maskValue(v any, op string) any {
	if v == nil {
		return nil
	}
	switch op {
	case "redact":
		return redactToken
	case "hash":
		sum := sha256.Sum256([]byte(toString(v)))
		return "sha256:" + hex.EncodeToString(sum[:])[:16]
	case "partial":
		return partialMask(toString(v))
	default:
		return redactToken
	}
}

// partialMask keeps the first and last rune, replacing the middle. Strings
// shorter than 3 runes are fully masked to avoid trivially recovering them.
func partialMask(s string) string {
	runes := []rune(s)
	n := len(runes)
	switch {
	case n == 0:
		return ""
	case n <= 2:
		return strings.Repeat("*", n)
	case n == 3:
		return string(runes[0]) + "**"
	default:
		return string(runes[0]) + strings.Repeat("*", n-2) + string(runes[n-1])
	}
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	default:
		// fmt is avoided here to keep masking independent of presentation;
		// numbers/bools are the only expected non-string scalars.
		return stringFromScalar(t)
	}
}
