package wgkey

import (
	"encoding/hex"
	"testing"
)

// RFC 7748 section 6.1 test vector (Alice).
func TestPublicMatchesRFC7748(t *testing.T) {
	privHex := "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	wantHex := "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
	var k Key
	b, _ := hex.DecodeString(privHex)
	copy(k[:], b)
	pub, err := k.Public()
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(pub[:]); got != wantHex {
		t.Fatalf("public key = %s, want %s", got, wantHex)
	}
}

func TestNewPrivateIsClampedAndUnique(t *testing.T) {
	a, err := NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewPrivate()
	if a == b {
		t.Fatal("two generated keys are identical")
	}
	if a[0]&7 != 0 || a[31]&128 != 0 || a[31]&64 == 0 {
		t.Fatalf("key not clamped: first=%08b last=%08b", a[0], a[31])
	}
}

func TestParseRoundTrip(t *testing.T) {
	k, _ := NewPreshared()
	got, err := Parse(" " + k.String() + "\n")
	if err != nil || got != k {
		t.Fatalf("round trip failed: %v", err)
	}
}

func TestParseRejectsBadInput(t *testing.T) {
	for _, s := range []string{"", "not base64!", "AAAA", "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo="} {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) accepted invalid key", s)
		}
	}
}
