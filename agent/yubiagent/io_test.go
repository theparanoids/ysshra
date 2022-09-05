// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

//nolint:all
package yubiagent

import (
	"bytes"
	"errors"
	"net"
	"testing"
)

func TestRead(t *testing.T) {
	data := append([]byte{0, 0, 0, 4}, []byte("test")...)
	buffer := bytes.NewBuffer(data)
	r, err := read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r, []byte("test")) {
		t.Logf("Expected: %v", []byte("test"))
		t.Logf("Actual: %v", r)
		t.Fatal("Function read isn't working properly.")
	}
	data = []byte{0xFF, 0xFF, 0xFF, 0xFF}
	buffer = bytes.NewBuffer(data)
	if _, err := read(buffer); err.Error()[:19] != "data size too large" {
		t.Fatalf("Failed to check the length limit: %v", err)
	}
}

func TestWrite(t *testing.T) {
	buffer := new(bytes.Buffer)
	if err := write(buffer, []byte("test")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buffer.Bytes(), append([]byte{0, 0, 0, 4}, []byte("test")...)) {
		t.Logf("Expected: %v", append([]byte{0, 0, 0, 4}, []byte("test")...))
		t.Logf("Actual: %v", buffer.Bytes())
		t.Fatal("Function yubiagent.write isn't working properly.")
	}
	if err := write(buffer, make([]byte, maxAgentResponseBytes+1)); err.Error()[:19] != "data size too large" {
		t.Fatalf("Failed to check the length limit: %v", err)
	}
}

// Mock net.Conn used for unit tests
type mockConn struct {
	net.Conn
	buffer    *bytes.Buffer
	closeFlag bool
}

func (fc *mockConn) Write(data []byte) (n int, err error) {
	if fc == nil {
		return 0, errors.New("nil mockConn in Write")
	}
	if fc.buffer == nil {
		return 0, errors.New("nil mockConn.buffer in Write")
	}
	return fc.buffer.Write(data)
}

func (fc mockConn) Read(data []byte) (n int, err error) {
	if fc.buffer == nil {
		return 0, errors.New("nil mockConn.buffer in Write")
	}
	return fc.buffer.Read(data)
}

func (fc *mockConn) Close() error {
	fc.closeFlag = true
	return nil
}

// Fake net.Conn that throw error when write
type mockConnNowr struct {
	net.Conn
}

func (fcnw mockConnNowr) Write(data []byte) (n int, err error) {
	return 0, errors.New("write error")
}
