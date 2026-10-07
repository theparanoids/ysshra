// Copyright 2026 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package yagent

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// reader decodes the agent wire format independently of the encoder, following
// parse_key_constraints in OpenSSH's ssh-agent.c.
type reader struct {
	t *testing.T
	b []byte
}

func (r *reader) byte() byte {
	r.t.Helper()
	if len(r.b) < 1 {
		r.t.Fatal("short read: byte")
	}
	v := r.b[0]
	r.b = r.b[1:]
	return v
}

func (r *reader) string() []byte {
	r.t.Helper()
	if len(r.b) < 4 {
		r.t.Fatal("short read: string length")
	}
	n := binary.BigEndian.Uint32(r.b)
	if uint32(len(r.b)-4) < n {
		r.t.Fatal("short read: string body")
	}
	v := r.b[4 : 4+n]
	r.b = r.b[4+n:]
	return v
}

func TestMarshalAddSmartcardKeyWithCerts(t *testing.T) {
	_, pub := newTestKey(t)
	exp := time.Now().Add(time.Hour)
	certs := []*ssh.Certificate{newTestCert(t, pub, "a", exp), newTestCert(t, pub, "b", exp)}

	r := &reader{t: t, b: marshalAddSmartcardKey("/lib/p11.so", []byte("123456"), certs)}
	if got := r.byte(); got != msgAddSmartcardKeyConstrained {
		t.Fatalf("message type = %d, want %d", got, msgAddSmartcardKeyConstrained)
	}
	if got := string(r.string()); got != "/lib/p11.so" {
		t.Fatalf("provider = %q", got)
	}
	if got := string(r.string()); got != "123456" {
		t.Fatalf("pin = %q", got)
	}
	if got := r.byte(); got != constrainExtension {
		t.Fatalf("constraint = %d, want %d", got, constrainExtension)
	}
	if got := string(r.string()); got != extAssociatedCerts {
		t.Fatalf("extension = %q", got)
	}
	if got := r.byte(); got != 0 {
		t.Fatalf("certs_only = %d, want 0", got)
	}
	blob := &reader{t: t, b: r.string()}
	for i, want := range certs {
		if got := blob.string(); !bytes.Equal(got, want.Marshal()) {
			t.Fatalf("cert %d does not round-trip", i)
		}
	}
	if len(blob.b) != 0 || len(r.b) != 0 {
		t.Fatalf("trailing bytes: blob=%d msg=%d", len(blob.b), len(r.b))
	}
}

func TestMarshalAddSmartcardKeyWithoutCerts(t *testing.T) {
	r := &reader{t: t, b: marshalAddSmartcardKey("/lib/p11.so", []byte("1"), nil)}
	if got := r.byte(); got != msgAddSmartcardKey {
		t.Fatalf("message type = %d, want %d", got, msgAddSmartcardKey)
	}
	r.string()
	r.string()
	if len(r.b) != 0 {
		t.Fatalf("unexpected constraints: %d bytes", len(r.b))
	}
}

// fakeAgent answers one request with resp and returns the request it saw.
func fakeAgent(t *testing.T, resp byte) (net.Conn, <-chan []byte) {
	t.Helper()
	client, server := net.Pipe()
	got := make(chan []byte, 1)
	go func() {
		defer func() { _ = server.Close() }()
		var length [4]byte
		if _, err := io.ReadFull(server, length[:]); err != nil {
			return
		}
		req := make([]byte, binary.BigEndian.Uint32(length[:]))
		if _, err := io.ReadFull(server, req); err != nil {
			return
		}
		got <- req
		_, _ = server.Write([]byte{0, 0, 0, 1, resp})
	}()
	t.Cleanup(func() { _ = client.Close() })
	return client, got
}

func TestRemoveSmartcardKey(t *testing.T) {
	conn, got := fakeAgent(t, msgSuccess)
	if err := RemoveSmartcardKey(conn, "/lib/p11.so"); err != nil {
		t.Fatal(err)
	}
	r := &reader{t: t, b: <-got}
	if typ := r.byte(); typ != msgRemoveSmartcardKey {
		t.Fatalf("message type = %d", typ)
	}
	if p := string(r.string()); p != "/lib/p11.so" {
		t.Fatalf("provider = %q", p)
	}
}

func TestAddSmartcardKeyFailure(t *testing.T) {
	conn, _ := fakeAgent(t, msgFailure)
	if err := AddSmartcardKey(conn, "/lib/p11.so", []byte("1"), nil); !errors.Is(err, ErrAgentFailure) {
		t.Fatalf("err = %v, want ErrAgentFailure", err)
	}
}

func TestMarshalCopiesPIN(t *testing.T) {
	// AddSmartcardKey zeroes its request after sending it. The PIN slice
	// belongs to the caller, so the request must copy it, not alias it.
	pin := []byte("123456")
	req := marshalAddSmartcardKey("/p", pin, nil)
	clear(req)
	if string(pin) != "123456" {
		t.Fatal("clearing the request clobbered the caller's PIN")
	}
}
