package main

import (
	"reflect"
	"testing"
)

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

func TestParseSSHKeyStream(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		force    bool
		want     []VNCKeyStroke
		wantRest []byte
	}{
		{
			name:  "plain chars",
			input: []byte("abc"),
			want: []VNCKeyStroke{
				{Key: 'a'},
				{Key: 'b'},
				{Key: 'c'},
			},
		},
		{
			name:  "ctrl chord",
			input: []byte{0x11},
			want: []VNCKeyStroke{
				{Key: 'q', Modifiers: []uint32{vncKeyControlL}},
			},
		},
		{
			name:  "alt char",
			input: []byte{0x1b, 'f'},
			want: []VNCKeyStroke{
				{Key: 'f', Modifiers: []uint32{vncKeyAltL}},
			},
		},
		{
			name:  "arrow with ctrl modifier",
			input: []byte("\x1b[1;5D"),
			want: []VNCKeyStroke{
				{Key: vncKeyLeft, Modifiers: []uint32{vncKeyControlL}},
			},
		},
		{
			name:  "shift tab",
			input: []byte("\x1b[Z"),
			want: []VNCKeyStroke{
				{Key: vncKeyTab, Modifiers: []uint32{vncKeyShiftL}},
			},
		},
		{
			name:  "f5",
			input: []byte("\x1b[15~"),
			want: []VNCKeyStroke{
				{Key: 0xFFC2},
			},
		},
		{
			name:  "delete",
			input: []byte("\x1b[3~"),
			want: []VNCKeyStroke{
				{Key: vncKeyDelete},
			},
		},
		{
			name:     "incomplete csi waits",
			input:    []byte("\x1b[1;5"),
			wantRest: []byte("\x1b[1;5"),
		},
		{
			name:  "forced lone escape",
			input: []byte{0x1b},
			force: true,
			want: []VNCKeyStroke{
				{Key: vncKeyEscape},
			},
		},
		{
			name:  "ss3 f1",
			input: []byte("\x1bOP"),
			want: []VNCKeyStroke{
				{Key: 0xFFBE},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, rest := parseSSHKeyStream(test.input, test.force)
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("parseSSHKeyStream(%q, %t) strokes = %#v, want %#v", test.input, test.force, got, test.want)
			}
			if !reflect.DeepEqual(rest, test.wantRest) {
				t.Fatalf("parseSSHKeyStream(%q, %t) rest = %#v, want %#v", test.input, test.force, rest, test.wantRest)
			}
		})
	}
}

func TestXtermModifierCodeToVNC(t *testing.T) {
	tests := []struct {
		mod  int
		want []uint32
	}{
		{2, []uint32{vncKeyShiftL}},
		{3, []uint32{vncKeyAltL}},
		{5, []uint32{vncKeyControlL}},
		{8, []uint32{vncKeyShiftL, vncKeyAltL, vncKeyControlL}},
	}

	for _, test := range tests {
		got := xtermModifierCodeToVNC(test.mod)
		if !reflect.DeepEqual(got, test.want) {
			t.Fatalf("xtermModifierCodeToVNC(%d) = %#v, want %#v", test.mod, got, test.want)
		}
	}
}
