package main

import "testing"

func TestControlByteToVNCKey(t *testing.T) {
	tests := []struct {
		input byte
		want  uint32
		ok    bool
	}{
		{0x03, 'c', true},
		{0x11, 'q', true},
		{0x18, 'x', true},
		{0x1c, '\\', true},
		{'\t', 0, false},
		{'\n', 0, false},
		{'\r', 0, false},
		{'a', 0, false},
	}

	for _, test := range tests {
		got, ok := controlByteToVNCKey(test.input)
		if got != test.want || ok != test.ok {
			t.Fatalf("controlByteToVNCKey(%#x) = (%#x, %t), want (%#x, %t)", test.input, got, ok, test.want, test.ok)
		}
	}
}
