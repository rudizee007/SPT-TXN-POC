package trustsnapshot

import (
	"bytes"
	"io"
)

// newTrimReader returns a reader over b with leading whitespace removed, so a
// pretty-printed body decodes identically to a compact one. Trailing content is
// still detected by the decoder's More() check — this trims, it does not forgive.
func newTrimReader(b []byte) io.Reader {
	return bytes.NewReader(bytes.TrimLeft(b, " \t\r\n"))
}
