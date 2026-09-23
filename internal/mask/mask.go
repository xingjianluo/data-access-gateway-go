package mask

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/xingjianluo/data-access-gateway-go/internal/policy"
)

// Apply 按脱敏规则返回脱敏后的数据副本，绝不原地修改输入。
// 规则中引用但记录中缺失的字段直接跳过；同一字段只出现一次（以首个规则为准）。
func Apply(in map[string]any, rules []policy.MaskRule) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	seen := map[string]bool{}
	for _, r := range rules {
		if seen[r.Field] {
			continue
		}
		seen[r.Field] = true
		if v, ok := out[r.Field]; ok {
			out[r.Field] = FieldValue(r.Method, r.Keep, v)
		}
	}
	return out
}

// FieldValue 按 method 计算单个字段的脱敏值：
//   - redact: 整体替换为 "***"；
//   - partial: 对字符串保留首尾 keep 个字符，中间以 * 替代；非字符串整体抹除；
//   - hash: 对值的字符串形式取 SHA-256（不可逆、稳定）。
//
// 未知 method 安全降级为 redact，绝不返回明文。
func FieldValue(method string, keep int, v any) any {
	switch method {
	case "redact":
		return "***"
	case "partial":
		s := fmt.Sprint(v)
		return partialMask(s, keep)
	case "hash":
		sum := sha256.Sum256([]byte(fmt.Sprint(v)))
		return "sha256:" + hex.EncodeToString(sum[:])
	default:
		return "***"
	}
}

func partialMask(s string, keep int) string {
	r := []rune(s)
	n := len(r)
	if keep <= 0 {
		return "***"
	}
	if n <= 2*keep {
		// 太短无法保留两端时整体抹除，避免保留过多信息。
		return "***"
	}
	return string(r[:keep]) + strings.Repeat("*", n-2*keep) + string(r[n-keep:])
}
