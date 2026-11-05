package server

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/windows/fileflags"
)

func TestMode(t *testing.T) {
	cases := []struct {
		access uint32
		want   string
	}{
		{fileflags.GENERIC_READ, "read"},
		{fileflags.FILE_READ_DATA, "read"},
		{fileflags.FILE_WRITE_DATA, "write"},
		{fileflags.FILE_APPEND_DATA, "write"},
		{fileflags.GENERIC_WRITE, "write"},
		{fileflags.GENERIC_ALL, "write"},
		{fileflags.DELETE, "write"},
		{fileflags.FILE_READ_DATA | fileflags.FILE_WRITE_DATA, "write"},
		{0, "read"},
	}
	for _, c := range cases {
		if got := mode(c.access); got != c.want {
			t.Errorf("mode(%#x) = %q, want %q", c.access, got, c.want)
		}
	}
}

func TestOpenAndxMode(t *testing.T) {
	cases := []struct {
		accessMode uint16
		want       string
	}{
		{0, "read"},
		{1, "write"},
		{2, "write"},
		{3, "read"}, // execute
		{0x40 | 1, "write"},
	}
	for _, c := range cases {
		if got := openAndxMode(c.accessMode); got != c.want {
			t.Errorf("openAndxMode(%#x) = %q, want %q", c.accessMode, got, c.want)
		}
	}
}
