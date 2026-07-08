package cell

import "io"

// Write encodes c and writes exactly Size bytes to w.
func Write(w io.Writer, c *Cell) error {
	_, err := w.Write(c.Marshal())
	return err
}

// Read reads exactly one Size-byte frame from r and decodes it. Framing is
// trivial precisely because cells are fixed size.
func Read(r io.Reader) (*Cell, error) {
	buf := make([]byte, Size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	c := &Cell{}
	if err := c.Unmarshal(buf); err != nil {
		return nil, err
	}
	return c, nil
}
