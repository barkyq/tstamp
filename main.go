package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"sync"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
)

var id_flag = flag.String("i", "", "commit id (defaults to whatever HEAD is pointing to)")
var proof_flag = flag.String("f", "", "generate merkle proof for filename (use with -i)")
var prove_commit_flag = flag.Bool("commit-proof", false, "generate merkle proof for the commit data")
var upgrade_flag = flag.Bool("u", false, "upgrade pending timestamps")
var delete_unsent = flag.Bool("d", false, "delete unsubmitted timestamps (use with -u)")
var calendars Calendars // see utils.go

func main() {
	flag.Var(&calendars, "c", "set calendars (can be used multiple times)")
	flag.Parse()

	proof_required := *proof_flag != "" || *prove_commit_flag

	var r *git.Repository
	if re, e := git.PlainOpen("."); e != nil {
		panic(e)
	} else {
		r = re
	}
	var calendar_ref_name plumbing.ReferenceName = "refs/timestamps/calendars"
	var calendar_ref *plumbing.Reference
	if len(calendars) > 0 {
		obj := r.Storer.NewEncodedObject()
		obj.SetType(plumbing.BlobObject)
		if w, e := obj.Writer(); e != nil {
			panic(e)
		} else {
			for _, c := range calendars {
				if c.Scheme != "https" {
					panic(fmt.Sprintf("%s: url scheme needs to be https", c.String()))
				} else if c.Host == "" {
					panic("empty hostname")
				} else if c.Port() == "" {
					c.Host = c.Host + ":443"
				}
				w.Write([]byte(c.String()))
				w.Write([]byte{'\r', '\n'})
			}
			w.Close()
		}
		if h, e := r.Storer.SetEncodedObject(obj); e != nil {
			panic(e)
		} else {
			c := plumbing.NewHashReference(calendar_ref_name, h)
			if e := r.Storer.SetReference(c); e != nil {
				panic(e)
			} else {
				fmt.Fprintf(os.Stderr, "%s updated\n", calendar_ref_name)
				return
			}
		}
	} else if ref, e := r.Reference(calendar_ref_name, false); e != nil || ref.Hash().IsZero() {
		calendar_ref = nil
	} else {
		calendar_ref = ref
	}

	var timestamp_ref_name plumbing.ReferenceName = "refs/timestamps/commits"
	var timestamp_ref *plumbing.Reference

	if t_ref, e := r.Reference(timestamp_ref_name, false); e != nil || t_ref.Hash().IsZero() {
		if ref, e := init_commit_ref(r, timestamp_ref_name); e == nil {
			timestamp_ref = ref
		} else {
			panic(e)
		}
	} else {
		timestamp_ref = t_ref
	}

	var pending_ref_name plumbing.ReferenceName = "refs/timestamps/pending"
	if *upgrade_flag {
		if calendar_ref == nil {
			fmt.Fprintln(os.Stderr, "set", calendar_ref_name, "using -c flag (can use more than once)")
			return
		}
		if cs, e := get_calendars(r, calendar_ref); e != nil {
			panic(e)
		} else {
			if e := upgrade_handler(r, pending_ref_name, timestamp_ref, cs); e != nil {
				if e == ErrPendingEmpty {
					fmt.Fprintln(os.Stderr, e)
					return
				} else {
					panic(e)
				}
			} else {
				// successful upgrade
				return
			}
		}
	}

	var commit_object *object.Commit
	if *id_flag != "" {
		if len(*id_flag) != 40 {
			panic("-i flag needs exactly 40 hexadecimal characters")
		} else if b, e := hex.DecodeString(*id_flag); e != nil {
			panic(e)
		} else {
			var tmp [20]byte
			copy(tmp[:], b)
			if c, e := r.CommitObject(plumbing.Hash(tmp)); e != nil {
				panic(fmt.Sprintf("invalid commit hash: %s", e))
			} else {
				commit_object = c
			}
		}
	} else if ref, e := r.Head(); e == nil {
		if c, e := r.CommitObject(ref.Hash()); e != nil {
			panic(fmt.Sprintf("invalid commit hash: %s", e))
		} else {
			commit_object = c
		}
	} else {
		panic(e)
	}

	var timestamp_already_exists bool
	var proof_footer io.ReadCloser
	if c, e := r.CommitObject(timestamp_ref.Hash()); e == nil {
		if f, e := c.File(commit_object.Hash.String()); e == nil {
			timestamp_already_exists = true
			if p, e := f.Reader(); e == nil {
				proof_footer = p
			} else {
				panic(e)
			}
		}
	} else {
		panic(e)
	}

	var footer_leaf []byte
	if proof_required {
		no_footer_error := fmt.Errorf("no proof footer for %s found in refs/timestamps/commit", commit_object.Hash)
		if proof_footer == nil {
			fmt.Fprintln(os.Stderr, no_footer_error)
			return
		}
		if b, e := ParseHeader(proof_footer); e != nil {
			if e == io.EOF {
				fmt.Fprintln(os.Stderr, no_footer_error)
				return
			} else {
				panic(e)
			}
		} else {
			footer_leaf = b
		}
	}

	var merkle_tree MerkleTree
	var target_leaf_hash [32]byte
	var target_git_id plumbing.Hash
	if proof_required || !timestamp_already_exists {
		var root_digest [32]byte
		if m, l, gid, e := merkle_tree_and_leaf_from_commit_object(r, commit_object, *proof_flag, *prove_commit_flag); e != nil {
			panic(e)
		} else {
			merkle_tree = m
			target_leaf_hash = l
			target_git_id = gid
			copy(root_digest[:], m.Digest())
		}
		if proof_required {
			var zeros [32]byte
			if target_leaf_hash == zeros {
				fmt.Fprintf(os.Stderr, "filename %s does not exist in %s\n", *proof_flag, commit_object.Hash)
				return
			}
		}
		fmt.Printf("computed merkle root: %x\n", root_digest)
		if !timestamp_already_exists {
			var pending_digest [53]byte
			pending_digest[0] = 0x00
			copy(pending_digest[1:21], commit_object.Hash[:])
			copy(pending_digest[21:53], root_digest[:])
			if e := append_blob_log_ref(r, pending_ref_name, pending_digest); e != nil {
				panic(e)
			}
		}
	}

	switch {
	case proof_required:
		proofs := make(chan Proof, 64)
		go merkle_tree.Proof([]Op{}, proofs, target_leaf_hash)
		var w io.Writer
		var filename string
		if *prove_commit_flag {
			filename = fmt.Sprintf("%s.ots", target_git_id)
		} else {
			filename = fmt.Sprintf("%s_%s.ots", *proof_flag, target_git_id)
		}
		if f, e := os.Create(filename); e == nil {
			defer f.Close()
			w = f
		} else {
			panic(e)
		}
		for p := range proofs {
			for k, by := range merkle_tree.Digest() {
				if footer_leaf[k] != by {
					panic("merkle tree digest does not match cached timestamp")
				}
			}
			if _, e := p.WriteTo(w); e != nil {
				panic(e)
			} else if _, e := io.Copy(w, proof_footer); e != nil {
				panic(e)
			}
		}
		fmt.Fprintf(os.Stderr, "proof saved to %s\n", filename)
	case !timestamp_already_exists:
		// store empty file
		blob_ob := r.Storer.NewEncodedObject()
		blob_ob.SetType(plumbing.BlobObject)
		if h, e := r.Storer.SetEncodedObject(blob_ob); e != nil {
			panic(e)
		} else {
			new_obj := object.TreeEntry{
				Name: commit_object.Hash.String(),
				Mode: filemode.Regular,
				Hash: h,
			}
			if _, e := push_tree_entries_to_commit_reference(r, timestamp_ref, []object.TreeEntry{new_obj}, nil); e != nil {
				panic(e)
			}
		}
		fmt.Println("run `tstamp -u` to submit digest to calendar servers")
	default:
		fmt.Fprintln(os.Stderr, "timestamp already exists for this commit\nuse -u flag to upgrade any pending timestamps\nuse -f flag to generate merkle proofs")
	}
}

func upgrade_handler(r *git.Repository, pending_ref_name plumbing.ReferenceName, timestamp_ref *plumbing.Reference, cs Calendars) error {
	if re, e := get_pending_queue(r, pending_ref_name); e != nil {
		return e
	} else {
		new_pending_queue := r.Storer.NewEncodedObject()
		new_pending_queue.SetType(plumbing.BlobObject)
		var new_pending_queue_writer io.WriteCloser
		if w, e := new_pending_queue.Writer(); e != nil {
			panic(e)
		} else {
			new_pending_queue_writer = w
		}
		new_tree_entries := make([]object.TreeEntry, 0)
		delete_entries := make([]string, 0)
		new_notes := make([]object.TreeEntry, 0)

		upgrade_chan := upgrade_pending_queue(timestamp_ref, r, re, cs)
		for upd := range upgrade_chan {
			if upd.Error != nil {
				panic(e)
			}
			switch upd.Digest[0] {
			case 0x01:
				// 0x01 means 0x00 -> 0x01 upgrade
				new_notes = add_note_to_new_tree(r, new_notes, fmt.Sprintf("pending timestamp submitted on %s", time.Now().Format("2006-01-02 15:04:05")), upd.Digest[1:21])
				// write to new tree and to pending queue
				new_tree_entries = add_upd_to_new_tree(r, new_tree_entries, upd)
				new_pending_queue_writer.Write(upd.Digest[:])
			case 0x02:
				// 0x02 means received BTC attestation
				new_notes = add_note_to_new_tree(r, new_notes, fmt.Sprintf("bitcoin attests existence as of height: %d", *upd.Height), upd.Digest[1:21])
				// do _not_ write to pending queue, as it is no longer pending
				new_tree_entries = add_upd_to_new_tree(r, new_tree_entries, upd)
			case 0x03:
				// 0x03 means still pending, no need to add to new tree
				// still write to new pending queue
				// flip the first byte 0x03 -> 0x01
				upd.Digest[0] = 0x01
				new_pending_queue_writer.Write(upd.Digest[:])
			case 0x04:
				// 0x04 means delete unsubmitted, no need to add to new tree
				delete_entries = append(delete_entries, fmt.Sprintf("%x", upd.Digest[1:21]))
			}
		}
		if len(new_notes) > 0 {
			var notes_ref_name plumbing.ReferenceName = "refs/notes/commits"
			var notes_ref *plumbing.Reference
			if ref, e := r.Reference(notes_ref_name, false); e != nil || ref.Hash().IsZero() {
				if ref, e := init_commit_ref(r, notes_ref_name); e == nil {
					notes_ref = ref
				} else {
					panic(e)
				}
			} else {
				notes_ref = ref
			}
			if _, e := push_tree_entries_to_commit_reference(r, notes_ref, new_notes, nil); e != nil {
				panic(e)
			}
		}
		if len(new_tree_entries) > 0 || len(delete_entries) > 0 {
			if _, e := push_tree_entries_to_commit_reference(r, timestamp_ref, new_tree_entries, delete_entries); e != nil {
				panic(e)
			}
		}
		// write new pending queue
		new_pending_queue_writer.Close()
		if h, e := r.Storer.SetEncodedObject(new_pending_queue); e != nil {
			panic(e)
		} else {
			if e := r.Storer.SetReference(plumbing.NewHashReference(pending_ref_name, h)); e != nil {
				panic(e)
			}
		}
	}
	return nil
}

// helper func
func add_note_to_new_tree(r *git.Repository, tree_entries []object.TreeEntry, note string, commit []byte) []object.TreeEntry {
	blob_ob := r.Storer.NewEncodedObject()
	blob_ob.SetType(plumbing.BlobObject)
	if w, e := blob_ob.Writer(); e != nil {
		panic(e)
	} else {
		w.Write([]byte(note))
		w.Close()
	}
	if h, e := r.Storer.SetEncodedObject(blob_ob); e != nil {
		panic(e)
	} else {
		new_note := object.TreeEntry{
			Name: fmt.Sprintf("%x", commit),
			Mode: filemode.Regular,
			Hash: h,
		}
		return append(tree_entries, new_note)
	}
}

// helper func
func add_upd_to_new_tree(r *git.Repository, tree_entries []object.TreeEntry, upd *Update) []object.TreeEntry {
	obj := r.Storer.NewEncodedObject()
	obj.SetType(plumbing.BlobObject)
	if w, e := obj.Writer(); e != nil {
		panic(e)
	} else {
		if _, e := WriteOTSHeader(w, upd.Digest[21:]); e != nil {
			panic(e)
		}
		if _, e := io.Copy(w, upd.Body); e != nil {
			panic(e)
		}
		if e := w.Close(); e != nil {
			panic(e)
		}
		if h, e := r.Storer.SetEncodedObject(obj); e != nil {
			panic(e)
		} else {
			new_tree_entry := object.TreeEntry{
				Name: fmt.Sprintf("%x", upd.Digest[1:21]),
				Mode: filemode.Regular,
				Hash: h,
			}
			return append(tree_entries, new_tree_entry)
		}
	}
}

func merkle_tree_and_leaf_from_commit_object(r *git.Repository, c *object.Commit, fn string, prove_commit bool) (MerkleTree, [32]byte, plumbing.Hash, error) {
	var target_leaf_hash [32]byte
	var gid plumbing.Hash
	hasher := sha256.New()
	hashes := make([][32]byte, 0)
	ctr, e := c.Tree()
	if e != nil {
		return nil, target_leaf_hash, gid, e
	}
	files := ctr.Files()
	o := r.Storer.NewEncodedObject()
	if e = c.Encode(o); e != nil {
		return nil, target_leaf_hash, gid, e
	}
	if re, e := o.Reader(); e != nil {
		return nil, target_leaf_hash, gid, e
	} else {
		io.Copy(hasher, re)
		var h [32]byte
		copy(h[:], hasher.Sum(nil))
		if prove_commit {
			target_leaf_hash = h
			gid = c.Hash
		}
		hashes = append(hashes, h)
		hasher.Reset()
		re.Close()
	}
	if e := files.ForEach(func(f *object.File) error {
		if r, e := f.Reader(); e != nil {
			return e
		} else {
			io.Copy(hasher, r)
			var h [32]byte
			copy(h[:], hasher.Sum(nil))
			if f.Name == fn && !prove_commit {
				target_leaf_hash = h
				gid = f.ID()
			}
			hashes = append(hashes, h)
			hasher.Reset()
			r.Close()
		}
		return nil
	}); e != nil {
		return nil, target_leaf_hash, gid, e
	}
	sort.Slice(hashes, func(i, j int) bool {
		for k := 0; k < 32; k++ {
			if hashes[i][k] < hashes[j][k] {
				return true
			} else if hashes[i][k] > hashes[j][k] {
				return false
			}
		}
		return false
	})
	nodes := make([]MerkleTree, 0)
	for _, h := range hashes {
		nodes = append(nodes, &Leaf{h})
	}
	for {
		if len(nodes) == 1 {
			break
		} else {
			a := nodes[0]
			b := nodes[1]
			fork := &Fork{Left: a, Right: b}
			nodes = nodes[2:]
			nodes = append(nodes, fork)
		}
	}
	return nodes[0], target_leaf_hash, gid, nil
}

var ErrAlreadyPending = fmt.Errorf("already in pending queue")
var ErrPendingEmpty = fmt.Errorf("pending queue is empty")

func append_to_pending_queue(w io.Writer, r io.Reader, digest [53]byte) (n int, e error) {
	var tmp [53]byte
	e = ErrAlreadyPending
	for {
		if r == nil {
			break
		}
		if _, err := r.Read(tmp[:]); tmp == digest {
			return
		} else if err == io.EOF {
			break
		} else if err != nil {
			err = e
			return
		} else if k, err := w.Write(tmp[:]); err != nil {
			e = err
			return
		} else {
			n += k
		}
	}
	if k, err := w.Write(digest[:]); err != nil {
		e = err
	} else {
		e = nil
		n += k
	}
	return
}

func get_calendars(r *git.Repository, ref *plumbing.Reference) (Calendars, error) {
	if blob, e := r.BlobObject(ref.Hash()); e != nil {
		return nil, e
	} else if re, e := blob.Reader(); e != nil {
		return nil, e
	} else {
		cs := make(Calendars, 0)
		scanner := bufio.NewScanner(re)
		for scanner.Scan() {
			if u, e := url.Parse(fmt.Sprintf("%s", scanner.Bytes())); e != nil {
				return nil, e
			} else {
				cs = append(cs, u)
			}
		}
		return cs, nil
	}
}

func get_pending_queue(r *git.Repository, name plumbing.ReferenceName) (io.ReadCloser, error) {
	if ref, e := r.Storer.Reference(name); e != nil || ref.Hash().IsZero() {
		return nil, ErrPendingEmpty
	} else if blob, e := r.BlobObject(ref.Hash()); e != nil {
		return nil, e
	} else if blob.Size == 0 {
		return nil, ErrPendingEmpty
	} else {
		return blob.Reader()
	}
}

type Update struct {
	Error  error
	Digest [53]byte
	Body   io.Reader
	Height *int64
}

func upgrade_pending_queue(timestamp_ref *plumbing.Reference, r *git.Repository, re io.Reader, cs Calendars) chan *Update {
	uchan := make(chan *Update)
	var tmp [53]byte
	var sha1_id plumbing.Hash
	var wg sync.WaitGroup
	var timestamps *object.Commit
	if c, e := r.CommitObject(timestamp_ref.Hash()); e == nil {
		timestamps = c
	} else {
		panic(e)
	}

	for {
		if _, e := re.Read(tmp[:]); e == io.EOF {
			break
		} else if e != nil {
			panic(e)
		}
		upd := new(Update)
		switch tmp[0] {
		case 0x00:
			if *delete_unsent {
				copy(upd.Digest[:], tmp[:])
				upd.Digest[0] = 0x04
				wg.Add(1)
				go func() {
					defer wg.Done()
					uchan <- upd
				}()
				continue
			}
			copy(upd.Digest[:], tmp[:])
			wg.Add(1)
			go OTS_submit(upd, uchan, &wg, cs)
		case 0x01:
			copy(upd.Digest[:], tmp[:])
			copy(sha1_id[:], tmp[1:21])
			if file, e := timestamps.File(sha1_id.String()); e != nil {
				panic(e)
			} else if b, e := file.Reader(); e != nil {
				panic(e)
			} else {
				upd.Body = b
				wg.Add(1)
				go func() {
					defer b.Close()
					OTS_upgrade(upd, uchan, &wg)
				}()
			}
		default:
			continue
		}
	}
	go func() {
		wg.Wait()
		close(uchan)
	}()
	return uchan
}

func append_blob_log_ref(repo *git.Repository, name plumbing.ReferenceName, digest [53]byte) error {
	blob_ob := repo.Storer.NewEncodedObject()
	blob_ob.SetType(plumbing.BlobObject)
	if w, e := blob_ob.Writer(); e != nil {
		return e
	} else {
		if ref, e := repo.Storer.Reference(name); e != nil || ref.Hash().IsZero() {
			if _, e := append_to_pending_queue(w, nil, digest); e != nil {
				panic(e)
			}
			goto jump
		} else if blob, e := repo.BlobObject(ref.Hash()); e != nil {
			panic(e)
		} else if r, e := blob.Reader(); e != nil {
			panic(e)
		} else if _, e := append_to_pending_queue(w, r, digest); e == ErrAlreadyPending {
			r.Close()
			return nil
		} else if e != nil {
			panic(e)
		}
	jump:
		w.Close()
		if h, e := repo.Storer.SetEncodedObject(blob_ob); e != nil {
			panic(e)
		} else {
			new_ref := plumbing.NewHashReference(name, h)
			return repo.Storer.SetReference(new_ref)
		}
	}
}

func init_commit_ref(r *git.Repository, name plumbing.ReferenceName) (*plumbing.Reference, error) {
	init_tree_ob := r.Storer.NewEncodedObject()
	init_tree_ob.SetType(plumbing.TreeObject)
	t, e := r.Storer.SetEncodedObject(init_tree_ob)
	if e != nil {
		return nil, e
	}
	init_commit_ob := r.Storer.NewEncodedObject()
	init_commit_ob.SetType(plumbing.CommitObject)
	w, e := init_commit_ob.Writer()
	if e != nil {
		return nil, e
	}

	w.Write([]byte(fmt.Sprintf("tree %s\n", t.String())))
	w.Write([]byte(fmt.Sprintf("author barkyq-git-bot <barkyq@localhost> %d -0400\n", time.Now().Unix())))
	w.Write([]byte(fmt.Sprintf("committer barkyq-git-bot <barkyq@localhost> %d -0400\n\ninit commit\n", time.Now().Unix())))
	w.Close()
	c, e := r.Storer.SetEncodedObject(init_commit_ob)
	if e != nil {
		return nil, e
	}

	ref := plumbing.NewHashReference(name, c)
	if e := r.Storer.SetReference(ref); e != nil {
		return nil, e
	}
	return ref, nil
}

func push_tree_entries_to_commit_reference(r *git.Repository, ref *plumbing.Reference, new_objs []object.TreeEntry, delete_entries []string) (*plumbing.Reference, error) {
	tree_ob := r.Storer.NewEncodedObject()
	tree_ob.SetType(plumbing.TreeObject)

	if w, e := tree_ob.Writer(); e != nil {
		return nil, e
	} else {
		var parent_tree []object.TreeEntry
		if c, e := r.CommitObject(ref.Hash()); e != nil {
			return nil, e
		} else {
			if t, e := c.Tree(); e != nil {
				return nil, e
			} else {
				parent_tree = t.Entries
			}
		}
	outer:
		for k, obj := range parent_tree {
			for _, delete_entry := range delete_entries {
				if obj.Name == delete_entry {
					parent_tree[k].Mode = filemode.Empty
					continue outer
				}
			}
			for l, new_obj := range new_objs {
				if obj.Name == new_obj.Name {
					parent_tree[k] = new_obj
					if l+1 < len(new_objs) {
						new_objs_b := new_objs[l+1:]
						new_objs = new_objs[:l]
						new_objs = append(new_objs, new_objs_b...)
					} else {
						new_objs = new_objs[:l]
					}
					break
				}
			}
			// fix malformed filemodes
			if tmp := parent_tree[k]; tmp.Mode.IsMalformed() {
				tmp.Mode = filemode.Regular
				parent_tree[k] = tmp
			}
		}
		for _, new_obj := range new_objs {
			parent_tree = append(parent_tree, new_obj)
		}
		sort.Slice(parent_tree, func(i, j int) bool {
			name_i := parent_tree[i].Name
			name_j := parent_tree[j].Name
			return name_i < name_j
		})
		var tmp [4]byte
		for _, obj := range parent_tree {
			copy(tmp[:], obj.Mode.Bytes())
			if tmp == [4]byte{0x00, 0x00, 0x00, 0x00} {
				fmt.Fprintf(os.Stderr, "deleting %s\n", obj.Name)
				continue
			}
			w.Write([]byte(obj.Mode.String()))
			w.Write([]byte{' '})
			w.Write([]byte(obj.Name))
			w.Write([]byte{0x00})
			w.Write(obj.Hash[:])
		}
	}

	t, e := r.Storer.SetEncodedObject(tree_ob)
	if e != nil {
		return nil, e
	}

	commit_ob := r.Storer.NewEncodedObject()
	commit_ob.SetType(plumbing.CommitObject)
	w, e := commit_ob.Writer()
	if e != nil {
		return nil, e
	}

	w.Write([]byte(fmt.Sprintf("tree %s\n", t)))
	w.Write([]byte(fmt.Sprintf("parent %s\n", ref.Hash())))
	w.Write([]byte(fmt.Sprintf("author barkyq-git-bot <barkyq@localhost> %d -0400\n", time.Now().Unix())))
	w.Write([]byte(fmt.Sprintf("committer barkyq-git-bot <barkyq@localhost> %d -0400\n\nautomated commit\n", time.Now().Unix())))
	w.Close()

	if c, e := r.Storer.SetEncodedObject(commit_ob); e != nil {
		return nil, e
	} else {
		new_ref := plumbing.NewHashReference(ref.Name(), c)
		if e := r.Storer.SetReference(new_ref); e != nil {
			return nil, e
		} else {
			return new_ref, e
		}
	}
}
