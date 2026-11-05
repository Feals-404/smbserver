package utils

import "testing"

func TestParseChallenge(t *testing.T) {
	ok := []struct {
		in   string
		want [8]byte
	}{
		{"1122334455667788", [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}},
		{"0x1122334455667788", [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}},
		{"  AABBCCDDEEFF0011 ", [8]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}},
	}
	for _, c := range ok {
		got, err := ParseChallenge(c.in)
		if err != nil {
			t.Errorf("ParseChallenge(%q) errored: %v", c.in, err)
			continue
		}
		if *got != c.want {
			t.Errorf("ParseChallenge(%q) = %x, want %x", c.in, *got, c.want)
		}
	}

	bad := []string{"", "11223344", "112233445566778899", "nothex!!nothex!!", "0x11"}
	for _, c := range bad {
		if _, err := ParseChallenge(c); err == nil {
			t.Errorf("ParseChallenge(%q) should have errored", c)
		}
	}
}

func TestParseOSVersion(t *testing.T) {
	ok := []struct {
		in           string
		major, minor byte
		build        uint16
	}{
		{"10.0.19041", 10, 0, 19041},
		{" 6.1.7601 ", 6, 1, 7601},
	}
	for _, c := range ok {
		got, err := ParseOSVersion(c.in)
		if err != nil {
			t.Errorf("ParseOSVersion(%q) errored: %v", c.in, err)
			continue
		}
		if got.ProductMajorVersion != c.major || got.ProductMinorVersion != c.minor || got.ProductBuild != c.build {
			t.Errorf("ParseOSVersion(%q) = %d.%d.%d, want %d.%d.%d", c.in,
				got.ProductMajorVersion, got.ProductMinorVersion, got.ProductBuild, c.major, c.minor, c.build)
		}
	}

	bad := []string{"", "10.0", "10.0.0.0", "10.0.x", "256.0.0", "10.0.70000", "-1.0.0"}
	for _, c := range bad {
		if _, err := ParseOSVersion(c); err == nil {
			t.Errorf("ParseOSVersion(%q) should have errored", c)
		}
	}
}
