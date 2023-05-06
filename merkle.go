package main

import (
	"crypto/sha256"
)

type MerkleTree interface {
	Digest() []byte
	Proof(footer []Op, proofs chan Proof, target_leaf_hash [32]byte) error
}

type Proof struct {
	Leaf  *Leaf
	Proof []Op
}

type Op struct {
	Tag byte
	Arg []byte
}

type Fork struct {
	digest []byte
	Left   MerkleTree
	Right  MerkleTree
}

func (f *Fork) Proof(footer []Op, proofs chan Proof, target_leaf_hash [32]byte) error {
	il := []Op{{0xf0, f.Right.Digest()}, {0x08, f.Digest()}}
	ir := []Op{{0xf1, f.Left.Digest()}, {0x08, f.Digest()}}
	il = append(il, footer...)
	ir = append(ir, footer...)
	if e := f.Left.Proof(il, proofs, target_leaf_hash); e != nil {
		return e
	}
	if e := f.Right.Proof(ir, proofs, target_leaf_hash); e != nil {
		return e
	}
	return nil
}

func (f *Fork) Digest() []byte {
	if len(f.digest) == 32 {
		return f.digest
	}
	h := sha256.New()
	h.Write(f.Left.Digest())
	h.Write(f.Right.Digest())
	f.digest = h.Sum(nil)
	return f.digest
}

type Leaf struct {
	digest [32]byte
}

func (v *Leaf) Proof(footer []Op, proofs chan Proof, target_leaf_hash [32]byte) error {
	if v.digest == target_leaf_hash {
		proofs <- Proof{v, footer}
		close(proofs)
	}
	return nil
}

func (v *Leaf) Digest() []byte {
	return v.digest[:]
}
