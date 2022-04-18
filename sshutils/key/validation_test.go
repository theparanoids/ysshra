// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package key

import (
	"os"
	"path/filepath"
	"testing"
)

func testLargeTmpFile(t *testing.T) string {
	tmpFile := filepath.Join(t.TempDir(), "large.file")
	f, err := os.Create(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(1e7); err != nil {
		t.Fatal(err)
	}
	return tmpFile
}

func Test_validateKeyFile(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		keyPath string
		wantErr bool
	}{
		{
			name:    "filepath invalid",
			keyPath: "invalid",
			wantErr: true,
		},
		{
			name:    "regular file",
			keyPath: "testdata/id_ecdsa.user.pub",
		},
		{
			name:    "file exceeds size limitation",
			keyPath: testLargeTmpFile(t),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateKeyFile(tt.keyPath); (err != nil) != tt.wantErr {
				t.Errorf("validateKeyFile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
