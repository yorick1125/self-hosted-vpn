//go:build !unix

package manager

// wgm only manages servers on Linux; this stub lets it build and run its
// tests on any OS.
func lock(string) (func(), error) { return func() {}, nil }
