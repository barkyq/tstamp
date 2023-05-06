package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// magic number
const MAJOR_VERSION = 0x01

// magic bytes
var BTC_attestation = [8]byte{0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01}
var Null_attestation = [8]byte{}
var Pending_attestation = [8]byte{0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e}
var HEADER_MAGIC = [31]byte{0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94}

func WriteOTSHeader(w io.Writer, digest []byte) (n int, e error) {
	if len(digest) < 32 {
		e = fmt.Errorf("digest needs to contain 32 bytes")
		return
	}

	var k int
	if k, e = w.Write(HEADER_MAGIC[:]); e != nil {
		return
	} else {
		n += k
	}
	if k, e = w.Write([]byte{MAJOR_VERSION, 0x08}); e != nil {
		return
	} else {
		n += k
	}
	k, e = w.Write(digest[:])
	n += k
	return
}

func OTS_submit(upd *Update, uchan chan *Update, wg *sync.WaitGroup, cs Calendars) error {
	defer wg.Done()
	pending_ts := make([]io.Reader, 0)
	for _, u := range cs {
		if r, e := SubmitDigest(u, upd.Digest[21:]); e != nil {
			fmt.Fprintln(os.Stderr, e)
			continue
		} else {
			pending_ts = append(pending_ts, r)
		}
	}
	if len(pending_ts) == 0 {
		return fmt.Errorf("no working calendars")
	}
	buf := bytes.NewBuffer(nil)
	for k, r := range pending_ts {
		if k+1 < len(pending_ts) {
			buf.Write([]byte{0xff})
		}
		if _, e := io.Copy(buf, r); e != nil {
			return e
		}
	}
	upd.Digest[0] = 0x01
	upd.Body = buf
	uchan <- upd
	return nil
}

func OTS_upgrade(upd *Update, uchan chan *Update, wg *sync.WaitGroup) error {
	defer wg.Done()
	var bitcoin_attestations []*Attestation
	if _, achan, e := Upgrade(upd.Body); e != nil {
		// parse the header
		return e
	} else {
		for a := range achan {
			bitcoin_attestations = append(bitcoin_attestations, a)
			if a.url != nil {
				fmt.Fprintf(os.Stderr, "%s: success! attestation received at height %d\n", a.url.Hostname(), a.height)
			} else {
				fmt.Fprintf(os.Stderr, "in file: %d\n", a.height)
			}
		}
	}
	if len(bitcoin_attestations) == 0 {
		upd.Digest[0] = 0x03
		uchan <- upd
		return nil
	} else {
		sort.SliceStable(bitcoin_attestations, func(i, j int) bool {
			return bitcoin_attestations[i].height < bitcoin_attestations[j].height
		})
	}
	buf := bytes.NewBuffer(nil)
	if _, e := buf.Write(bitcoin_attestations[0].body); e != nil {
		return e
	} else {
		upd.Height = &(bitcoin_attestations[0].height)
		upd.Body = buf
		upd.Digest[0] = 0x02
		uchan <- upd
		return nil
	}
}

type Attestation struct {
	body   []byte
	height int64
	url    *url.URL
}

// Upgrade takes a pending .ots file and returns the leaf digest and a channel with upgraded attestations.
func Upgrade(r io.Reader) ([]byte, chan *Attestation, error) {
	achan := make(chan *Attestation)
	var wg sync.WaitGroup
	if l, err := ParseHeader(r); err != nil {
		return nil, nil, err
	} else {
		wg.Add(1)
		go func() {
			defer close(achan)
			if err = upgrade_timestamp(r, l, nil, achan, &wg, nil); err != nil {
				panic(err)
			}
			wg.Wait()
		}()
		return l, achan, nil
	}
}

// upgrade helper function
func upgrade_timestamp(r io.Reader, leaf []byte, prefix []byte, achan chan *Attestation, wg *sync.WaitGroup, url *url.URL) (err error) {
	defer wg.Done()
	buf := bytes.NewBuffer(nil)
	buf.Write(prefix)
	result := make([]byte, 0)
	result = append(result, leaf...)
	var attestation [8]byte
	var tag [1]byte
	sha256 := sha256.New()

	for {
		if _, err = r.Read(tag[:]); err != nil {
			return
		}
		switch {
		case tag[0] == 0x08:
			buf.Write(tag[:])
			sha256.Reset()
			if _, err = sha256.Write(result); err != nil {
				return
			}
			result = sha256.Sum(nil)
		case tag[0] == 0xf1 || tag[0] == 0xf0:
			buf.Write(tag[:])
			j := read_varint(r)
			write_varint(buf, j)
			piece := make([]byte, j)
			if _, err = io.ReadFull(r, piece); err != nil {
				return
			}
			buf.Write(piece)
			switch tag[0] {
			case 0xf1:
				result = append(piece, result...)
			case 0xf0:
				result = append(result, piece...)
			}
		case tag[0] == 0x00:
			if _, err = io.ReadFull(r, attestation[:]); err != nil {
				return
			}
			return upgrade_attestation(r, attestation, result, buf.Bytes(), achan, wg, url)
		case tag[0] == 0xff:
			wg.Add(1)
			if err = upgrade_timestamp(r, result, buf.Bytes(), achan, wg, url); err != nil {
				return
			}
		default:
			err = fmt.Errorf("unknown tag")
			return
		}
	}
}

// upgrade helper function
func upgrade_attestation(r io.Reader, attestation [8]byte, result []byte, prefix []byte, achan chan *Attestation, wg *sync.WaitGroup, url *url.URL) (e error) {
	switch attestation {
	case BTC_attestation:
		buf := bytes.NewBuffer(nil)
		buf.Write(prefix)
		buf.Write([]byte{0x00})
		buf.Write(attestation[:])
		j := read_varint(r)
		write_varint(buf, j)
		j = read_varint(r)
		write_varint(buf, j)
		if mroot, e := MerkleRoot(j); e == nil {
			for k, b := range mroot {
				if b != result[32-k-1] {
					fmt.Fprintf(os.Stderr, "%s: height %d light-client verification failed!\n", url.Hostname(), j)
					return nil
				}
			}
			achan <- &Attestation{buf.Bytes(), j, url}
		} else {
			return e
		}
		return
	case Pending_attestation:
		j := read_varint(r)
		raw_url := make([]byte, j)
		io.ReadFull(r, raw_url)
		if URL, err := url.Parse(fmt.Sprintf("%s/timestamp/%x", raw_url[1:], result)); err != nil {
			return err
		} else {
			if ur, err := GetTimestamp(URL); err != nil {
				return err
			} else {
				var tester [1]byte
				ur.Read(tester[:])
				msg := bytes.NewBuffer(tester[:])
				io.Copy(msg, ur)
				if tester[0] != 0x08 && tester[0] != 0xf0 && tester[0] != 0xf1 {
					fmt.Fprintf(os.Stderr, "%s: %s\n", URL.Hostname(), msg.Bytes())
					return
				} else {
					wg.Add(1)
					return upgrade_timestamp(msg, result, prefix, achan, wg, URL)
				}
			}
		}
	default:
		return fmt.Errorf("unknown attestation")
	}
}

// ParseHeader parses an OpenTimestamps header and returns the leaf digest.
func ParseHeader(r io.Reader) ([]byte, error) {
	var magic [31]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return nil, err
	} else {
		if magic != HEADER_MAGIC {
			return nil, fmt.Errorf("Invalid Header Magic!")
		}
	}
	r.Read(magic[:1])
	if magic[0] != MAJOR_VERSION {
		return nil, fmt.Errorf("Incompatible Major Version!")
	}
	r.Read(magic[:1])
	hash_type := magic[0]
	var hash_length int64
	switch hash_type {
	case 0x08:
		hash_length = 32
	default:
		return nil, fmt.Errorf("Unknown Hash Type!")
	}
	leaf := make([]byte, hash_length)
	_, err := io.ReadFull(r, leaf)
	return leaf, err
}

// SubmitDigest takes URL of form https://calendar.com/ and a digest to be posted.
// Returns a reader containing the response
func SubmitDigest(URL *url.URL, digest []byte) (r io.Reader, err error) {
	var conn io.ReadWriter
	if c, e := tls.Dial("tcp", URL.Host, &tls.Config{ServerName: URL.Hostname()}); e != nil {
		err = e
		return
	} else {
		conn = c
	}
	wb := bufio.NewWriter(conn)
	wb.Write([]byte(fmt.Sprint("POST /digest HTTP/1.1\r\n")))
	wb.Write([]byte(fmt.Sprintf("Host: %s\r\n", URL.Hostname())))
	wb.Write([]byte("User-Agent: barkyq-http-client/1.0\r\n"))
	wb.Write([]byte("Accept: application/vnd.opentimestamps.v1\r\n"))
	wb.Write([]byte("Content-Type: application/x-www-form-urlencoded\r\n"))
	wb.Write([]byte("Content-Length: 32\r\n"))
	wb.Write([]byte("\r\n"))
	wb.Write(digest)
	wb.Flush()

	rb := bufio.NewReader(conn)
	return read_chunked(rb)
}

// helper for reading chunked data
func read_chunked(rb *bufio.Reader) (r io.Reader, err error) {
	var chunked bool
	var content_encoding string
	for {
		header_line, err := rb.ReadString('\n')
		if err != nil {
			panic(err)
		}
		if arr := strings.Split(header_line, ":"); len(arr) > 1 {
			key := strings.TrimSpace(strings.ToLower(arr[0]))
			val := strings.TrimSpace(strings.ToLower(arr[1]))
			switch key {
			case "transfer-encoding":
				if val == "chunked" {
					chunked = true
				}
			case "content-encoding":
				content_encoding = val
			default:
			}
		}
		if header_line == "\r\n" {
			// break at the empty CRLF
			break
		}
	}
	_, _ = chunked, content_encoding

	if chunked {
		var tmp [32]byte
		data_buf := bytes.NewBuffer(nil)
		for {
			chunk, e := rb.ReadString('\n')
			if e != nil {
				err = e
				return
			}
			chunk_size, e := strconv.ParseInt(strings.TrimSpace(chunk), 16, 64)
			if e != nil {
				err = e
				return
			}
			if chunk_size == 0 {
				rb.Discard(2)
				// finished chunking
				break
			}
			for chunk_size > 32 {
				if n, e := rb.Read(tmp[:]); e == nil {
					chunk_size -= int64(n)
					data_buf.Write(tmp[:n])
				} else {
					err = e
					return
				}
			}
			if n, err := rb.Read(tmp[:chunk_size]); err == nil {
				data_buf.Write(tmp[:n])
			}
			// chunk size does not account for CRLF added to end of chunk data
			rb.Discard(2)
		}
		return data_buf, nil
	} else {
		return rb, nil
	}
}

const blockstream = "blockstream.info"

func MerkleRoot(height int64) ([]byte, error) {
	var conn io.ReadWriter
	if c, e := tls.Dial("tcp", blockstream+":443", &tls.Config{ServerName: blockstream}); e != nil {
		return nil, e
	} else {
		conn = c
	}
	wb := bufio.NewWriter(conn)
	wb.Write([]byte(fmt.Sprintf("GET /api/block-height/%d HTTP/1.1\r\n", height)))
	wb.Write([]byte(fmt.Sprintf("Host: %s\r\n", blockstream)))
	wb.Write([]byte("User-Agent: barkyq-http-client/1.0\r\n"))
	wb.Write([]byte("Accept: plain/text\r\n"))
	wb.Write([]byte("\r\n"))
	wb.Flush()

	rb := bufio.NewReader(conn)
	var hex_hash [64]byte
	if r, err := read_chunked(rb); err != nil {
		return nil, err
	} else {
		r.Read(hex_hash[:])
	}
	wb.Write([]byte(fmt.Sprintf("GET /api/block/%s HTTP/1.1\r\n", hex_hash)))
	wb.Write([]byte(fmt.Sprintf("Host: %s\r\n", blockstream)))
	wb.Write([]byte("User-Agent: barkyq-http-client/1.0\r\n"))
	wb.Write([]byte("Accept: application/json\r\n"))
	wb.Write([]byte("\r\n"))
	wb.Flush()
	if r, err := read_chunked(rb); err != nil {
		return nil, err
	} else {
		dec := json.NewDecoder(r)
		m := make(map[string]any)
		dec.Decode(&m)
		if merkle_root, ok := m["merkle_root"].(string); ok != true {
			return nil, fmt.Errorf("invalid merkle root")
		} else {
			return hex.DecodeString(merkle_root)
		}
	}
}

// GetTimestamp takes a URL of form "https://calendar.com/timestamp/TIMESTAMP_HEX".
// Returns r containing the response (a Proof fragment, missing the header).
func GetTimestamp(URL *url.URL) (r io.Reader, err error) {
	var conn io.ReadWriter
	if c, e := tls.Dial("tcp", URL.Hostname()+":443", &tls.Config{ServerName: URL.Hostname()}); e != nil {
		err = e
		return
	} else {
		conn = c
	}
	wb := bufio.NewWriter(conn)
	wb.Write([]byte(fmt.Sprintf("GET %s HTTP/1.1\r\n", URL.Path)))
	wb.Write([]byte(fmt.Sprintf("Host: %s\r\n", URL.Hostname())))
	wb.Write([]byte("User-Agent: barkyq-http-client/1.0\r\n"))
	wb.Write([]byte("Accept: application/vnd.opentimestamps.v1\r\n"))
	wb.Write([]byte("Content-Type: application/x-www-form-urlencoded\r\n"))
	wb.Write([]byte("\r\n"))
	wb.Flush()

	rb := bufio.NewReader(conn)
	return read_chunked(rb)
}
