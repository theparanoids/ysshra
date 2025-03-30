// Code generated by MockGen. DO NOT EDIT.
// Source: ./handler/smartcard/verifier/slot.go

// Package verifier is a generated GoMock package.
package yubiagent

import (
	"crypto/x509"
	"reflect"

	gomock "github.com/golang/mock/gomock"
	keyid "github.com/theparanoids/ysshra/keyid"
	ssh "golang.org/x/crypto/ssh"
)

// Mockslot is a mock of slot interface.
type Mockslot struct {
	ctrl     *gomock.Controller
	recorder *MockslotMockRecorder
}

// MockslotMockRecorder is the mock recorder for Mockslot.
type MockslotMockRecorder struct {
	mock *Mockslot
}

// NewMockslot creates a new mock instance.
func NewMockslot(ctrl *gomock.Controller) *Mockslot {
	mock := &Mockslot{ctrl: ctrl}
	mock.recorder = &MockslotMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *Mockslot) EXPECT() *MockslotMockRecorder {
	return m.recorder
}

// attestSlot mocks base method.
func (m *Mockslot) attestSlot(arg0 *x509.Certificate, arg1, arg2 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "attestSlot", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// attestSlot indicates an expected call of attestSlot.
func (mr *MockslotMockRecorder) attestSlot(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "attestSlot", reflect.TypeOf((*Mockslot)(nil).attestSlot), arg0, arg1, arg2)
}

// getPolicy mocks base method.
func (m *Mockslot) getPolicy() keyid.TouchPolicy {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "getPolicy")
	ret0, _ := ret[0].(keyid.TouchPolicy)
	return ret0
}

// getPolicy indicates an expected call of getPolicy.
func (mr *MockslotMockRecorder) getPolicy() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "getPolicy", reflect.TypeOf((*Mockslot)(nil).getPolicy))
}

// getPublicKey mocks base method.
func (m *Mockslot) getPublicKey() ssh.PublicKey {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "getPublicKey")
	ret0, _ := ret[0].(ssh.PublicKey)
	return ret0
}

// getPublicKey indicates an expected call of getPublicKey.
func (mr *MockslotMockRecorder) getPublicKey() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "getPublicKey", reflect.TypeOf((*Mockslot)(nil).getPublicKey))
}

// getSerial mocks base method.
func (m *Mockslot) getSerial() (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "getSerial")
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// getSerial indicates an expected call of getSerial.
func (mr *MockslotMockRecorder) getSerial() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "getSerial", reflect.TypeOf((*Mockslot)(nil).getSerial))
}

// getSlotCode mocks base method.
func (m *Mockslot) getSlotCode() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "getSlotCode")
	ret0, _ := ret[0].(string)
	return ret0
}

// getSlotCode indicates an expected call of getSlotCode.
func (mr *MockslotMockRecorder) getSlotCode() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "getSlotCode", reflect.TypeOf((*Mockslot)(nil).getSlotCode))
}
