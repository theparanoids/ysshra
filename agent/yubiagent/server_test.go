// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

//nolint:all
package yubiagent

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"sync"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/net/nettest"
)

// createPublicKey create public and privaty key pairs for unit tests.
func createPublicKey() (*rsa.PrivateKey, ssh.PublicKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

// testServer creates a yubiagent server for unit tests
func testServer(t *testing.T) YubiAgent {
	ag := agent.NewKeyring()

	listener, err := nettest.NewLocalListener("unix")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		listener.Close()
	})

	var wg sync.WaitGroup
	serve := func() error {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		wg.Done()
		return agent.ServeAgent(ag, conn)
	}
	go func() {
		for {
			wg.Add(1)
			go serve()
			wg.Wait()
		}
	}()

	// remote needs to be true because the yubico-piv-tool doesn't exist in the unit test.
	s, err := NewServer(listener.Addr().String(), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.Close()
	})
	return s
}

func TestServerForward(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	ag := NewMockShimAgent(ctrl)

	gomock.InOrder(
		ag.EXPECT().Forward([]byte{AgentMessageRequestIdentities}).Return([]byte{12 /* List return type */, 0, 0, 0, 0 /* 0 keys*/}, nil),
		ag.EXPECT().Forward([]byte{AgentMessageRequestIdentities}).Return(nil, errors.New("some error")),
	)

	s := &server{ShimAgent: ag}
	got, err := s.Forward([]byte{AgentMessageRequestIdentities})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	want := []byte{12 /* List return type */, 0, 0, 0, 0 /* 0 keys*/}
	if !bytes.Equal(got, want) {
		t.Errorf("expect %v, got %#+v", want, got)
	}

	_, err = ag.Forward([]byte{AgentMessageRequestIdentities})
	if err == nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestServerAddHardCert(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	ag := NewMockShimAgent(ctrl)

	_, key, err := createPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	ag.EXPECT().AddHardCert(key, "on-the-fly-pub").Return(nil)

	s := &server{ShimAgent: ag}
	if err = s.AddHardCert(key, "on-the-fly-pub"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestServerClose(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	ag := NewMockShimAgent(ctrl)
	ag.EXPECT().Close().Return(nil)

	s := &server{ShimAgent: ag}
	if err := s.Close(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestServerList(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	ag := NewMockShimAgent(ctrl)

	want := []*agent.Key{
		{Format: "format", Comment: "comment"},
	}
	ag.EXPECT().List().Return(want, nil)

	s := &server{ShimAgent: ag}
	got, err := s.List()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !cmp.Equal(got, want) {
		t.Errorf("unexpected result: diff(-got,+want):\n%v", cmp.Diff(got, want))
	}
}

func TestServerSign(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	ag := NewMockShimAgent(ctrl)

	priv, pub, err := createPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 1024)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	want, err := signer.Sign(rand.Reader, data)
	if err != nil {
		t.Fatal(err)
	}
	ag.EXPECT().Sign(pub, data).DoAndReturn(func(pub ssh.PublicKey, data []byte) (*ssh.Signature, error) {
		return signer.Sign(rand.Reader, data)
	})

	s := &server{ShimAgent: ag}
	got, err := s.Sign(pub, data)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !cmp.Equal(got, want) {
		t.Errorf("unexpected result: diff(-got,+want):\n%v", cmp.Diff(got, want))
	}
}

func TestServerAdd(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	ag := NewMockShimAgent(ctrl)

	priv, _, err := createPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	added := agent.AddedKey{
		PrivateKey: priv,
		Comment:    "comment",
	}
	ag.EXPECT().Add(added).Return(nil)

	s := &server{ShimAgent: ag}
	if err := s.Add(added); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestServerRemove(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	ag := NewMockShimAgent(ctrl)

	_, pub, err := createPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	ag.EXPECT().Remove(pub).Return(nil)

	s := &server{ShimAgent: ag}
	if err := s.Remove(pub); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestServerRemoveAll(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	ag := NewMockShimAgent(ctrl)

	ag.EXPECT().RemoveAll().Return(nil)

	s := &server{ShimAgent: ag}
	if err := s.RemoveAll(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestServerLock(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	ag := NewMockShimAgent(ctrl)

	ag.EXPECT().Lock([]byte("on-the-fly")).Return(nil)

	s := &server{ShimAgent: ag}
	if err := s.Lock([]byte("on-the-fly")); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestServerUnlock(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	ag := NewMockShimAgent(ctrl)

	ag.EXPECT().Unlock([]byte("on-the-fly")).Return(nil)

	s := &server{ShimAgent: ag}
	if err := s.Unlock([]byte("on-the-fly")); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestServerSigners(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	ag := NewMockShimAgent(ctrl)

	priv, _, err := createPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	want := []ssh.Signer{signer}
	ag.EXPECT().Signers().Return(want, nil)

	s := &server{ShimAgent: ag}
	got, err := s.Signers()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	compareSigner := cmp.Options{
		cmp.Comparer(func(x, y ssh.Signer) bool {
			return x == y
		}),
	}
	if !cmp.Equal(got, want, compareSigner...) {
		t.Errorf("unexpected result: diff(-got,+want):\n%v", cmp.Diff(got, want, compareSigner...))
	}
}

func TestServerAddSmartcardKey(t *testing.T) {
	t.Parallel()
	s := testServer(t)
	if err := s.AddSmartcardKey("/path/to/lib", []byte("123"), 0, false); err == nil {
		t.Fatal("unexpected error: want non-nil error")
	}
}

func TestServerRemoveSmartcardKey(t *testing.T) {
	t.Parallel()
	s := testServer(t)
	if err := s.RemoveSmartcardKey("/path/to/lib", nil); err == nil {
		t.Fatal("unexpected error: want non-nil error")
	}
}
