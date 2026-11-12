package cmd

import "testing"

func TestSafeBaseName(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "file.txt", want: "file.txt"},
		{in: "some/sub/dir/file.txt", want: "file.txt"},
		{in: "/etc/passwd", want: "passwd"},
		{in: "..\\..\\windows\\system32\\evil.dll", want: "evil.dll"},
		{in: `a\b\c.txt`, want: "c.txt"},
		{in: ".", wantErr: true},
		{in: "..", wantErr: true},
		{in: "", wantErr: true},
		{in: "/", wantErr: true},
		{in: ".bashrc", want: ".bashrc"},
		{in: "archive.tar.gz", want: "archive.tar.gz"},
		{in: "dir/", want: "dir"},
	}
	for _, tc := range cases {
		got, err := safeBaseName(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("safeBaseName(%q) = %q, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("safeBaseName(%q) error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("safeBaseName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestZipPathContained(t *testing.T) {
	dir := "/tmp/outdir"
	cases := []struct {
		p    string
		want bool
	}{
		{"/tmp/outdir/file.txt", true},
		{"/tmp/outdir/sub/dir/file.txt", true},
		{"/tmp/outdir/..", false},
		{"/tmp/outdir/../outdir-evil/x", false},
		{"/tmp/outdir2/x", false},
		{"/tmp/out-dir/x", false},
		{"/tmp/outdirx/x", false},
		{"/tmp/outdir", true},
	}
	for _, tc := range cases {
		if got := zipPathContained(dir, tc.p); got != tc.want {
			t.Errorf("zipPathContained(%q, %q) = %v, want %v", dir, tc.p, got, tc.want)
		}
	}
}
