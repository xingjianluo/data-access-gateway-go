package gateway

import "strconv"

// stringFromScalar renders the limited scalar set stored in records.
func stringFromScalar(v any) string {
	switch t := v.(type) {
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		// Anything compound is hashed as an empty-safe placeholder only
		// after callers have redirected it to full redaction.
		return ""
	}
}
