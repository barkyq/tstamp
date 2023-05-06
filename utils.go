package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
)

type Calendars []*url.URL

func (cs *Calendars) String() (str string) {
	for _, val := range *cs {
		str += fmt.Sprintf(" %s", val.String())
	}
	return
}
func (cs *Calendars) Set(value string) error {
	if u, e := url.Parse(value); e != nil {
		return e
	} else {
		*cs = append(*cs, u)
	}
	return nil
}

func write_varint(w io.Writer, j int64) (int64, error) {
	if j < 0 {
		return 0, fmt.Errorf("must be non-negative")
	}
	for {
		if j > 127 {
			if _, e := w.Write([]byte{128 + byte(j%128)}); e != nil {
				return 0, e
			}
			j = j / 128
		} else {
			k, e := w.Write([]byte{byte(j)})
			return int64(k), e
		}
	}
}

func read_varint(r io.Reader) (j int64) {
	var b [1]byte
	builder := make([]byte, 0)
	for {
		if _, e := r.Read(b[:]); e != nil {
			panic(e)
		}
		if b[0] > 128 {
			builder = append(builder, b[0]-128)
		} else {
			builder = append(builder, b[0])
			break
		}
	}
	var power int64 = 1
	for _, v := range builder {
		j += int64(v) * power
		power *= 128
	}
	return
}

func (p *Proof) WriteTo(f io.Writer) (n int64, err error) {
	if k, e := f.Write(HEADER_MAGIC[:]); e != nil {
		err = e
		return
	} else {
		n += int64(k)
	}
	if k, e := f.Write([]byte{MAJOR_VERSION, 0x08}); e != nil {
		err = e
		return
	} else {
		n += int64(k)
	}
	if k, e := f.Write(p.Leaf.digest[:]); e != nil {
		err = e
		return
	} else {
		n += int64(hex.EncodedLen(k))
	}
	for _, i := range p.Proof {
		if k, e := f.Write([]byte{i.Tag}); e != nil {
			err = e
			return
		} else {
			n += int64(k)
		}
		switch {
		case i.Tag == 0xf1 || i.Tag == 0xf0:
			if k, e := write_varint(f, int64(len(i.Arg))); e != nil {
				err = e
				return
			} else {
				n += int64(k)
			}
			if k, e := f.Write(i.Arg); e != nil {
				err = e
				return
			} else {
				n += int64(k)
			}
		}
	}
	return
}
