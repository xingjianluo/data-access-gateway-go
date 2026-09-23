package mask

import (
	"strings"
	"testing"

	"github.com/xingjianluo/data-access-gateway-go/internal/policy"
)

func TestApply(t *testing.T) {
	in := map[string]any{
		"name":  "alice",
		"email": "alice@example.com",
		"ssn":   "123-45-6789",
	}
	rules := []policy.MaskRule{
		{Field: "email", Method: "partial", Keep: 1},
		{Field: "ssn", Method: "redact"},
		{Field: "missing", Method: "redact"}, // 缺失字段跳过
	}
	out := Apply(in, rules)
	t.Logf("INPUT : %v", in)
	t.Logf("RULES : %+v", rules)
	t.Logf("OUTPUT: %v", out)

	if out["ssn"] != "***" {
		t.Fatalf("redact failed: %v", out["ssn"])
	}
	if !strings.HasPrefix(out["email"].(string), "a") ||
		!strings.HasSuffix(out["email"].(string), "m") {
		t.Fatalf("partial mask should keep first/last char: %v", out["email"])
	}
	if strings.Contains(out["email"].(string), "@") {
		t.Fatalf("middle must be masked: %v", out["email"])
	}
	if in["ssn"] != "123-45-6789" {
		t.Fatal("Apply must not mutate input")
	}
	if in["name"] != out["name"] {
		t.Fatal("unlisted field should pass through")
	}
}

func TestFieldValueHashStable(t *testing.T) {
	h1 := FieldValue("hash", 0, "secret")
	h2 := FieldValue("hash", 0, "secret")
	h3 := FieldValue("hash", 0, "other")
	t.Logf("hash(secret)=%v hash(other)=%v", h1, h3)
	if h1 != h2 {
		t.Fatal("hash must be deterministic")
	}
	if h1 == h3 {
		t.Fatal("different inputs must hash differently")
	}
	if FieldValue("unknown-method", 0, "x") != "***" {
		t.Fatal("unknown method must safely degrade to redact")
	}
}
