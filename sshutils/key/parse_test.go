// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package key

import (
	"bytes"
	"os"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// TestGetPrivateKeyFromFile tests GetPrivateKeyFromFile to read the privkey from key file.
func TestGetPrivateKeyFromFile(t *testing.T) {
	t.Parallel()
	_, err := GetPrivateKeyFromFile("./testdata/non-exist")
	if !os.IsNotExist(err) {
		t.Errorf("unexpected error %v", err)
	}
	_, err = GetPrivateKeyFromFile("./testdata/rsa2048.pem")
	if err != nil {
		t.Errorf("unexpected error %v", err)
	}
	_, err = GetPrivateKeyFromFile("./testdata/rsa_BROKEN.pem")
	if err == nil {
		t.Errorf("expect an error here.")
	}
}

// TestGetPublicKeyFromFile tests GetPublicKeyFromFile to read the pubkey from the public key file.
func TestGetPublicKeyFromFile(t *testing.T) {
	t.Parallel()
	cases := []struct {
		filename string
		comment  string
		key      []byte
	}{
		{"./testdata/id_rsa.user.pub", "test@example.com", []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDNEWjcPtgb3A7amx/UhlBeSPMxnAVmX0yyCz5mZ80zFbkYXcrqPnwlomuriiivWfW6qRqYHZFxf+6xjodr1M7BgM6+5Ngp8wEeGDSgbE2fq2EVgT3wwNC5Cyr/ruGSgQmdusEBY1NrXJ9cXg0LvtCb2QlZjmY7JAY1fgmPQmNvoZm6zzoRZFB7K3zuiBXTJfxxlMLrMt5sXjeN/KFvDa/q5JXCKUD58MQikbVk1D4gW0Ta37Q9g5GshnS4jcmRY2CHulJ5IWwGXPicql4t9cPT9g1P90T4DrtevW4mHpkGwi0FdbEOgO2S6poCFYCoCx+Q11xUBchKo4n9VgNGHBul\n")},
		{"./testdata/id_rsa.user-cert.pub", "test@example.com", []byte("ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgbzrh1I5VTIwvyTmh0LhnV2hgotmGltvlBE6SC3SL+G0AAAADAQABAAABAQDNEWjcPtgb3A7amx/UhlBeSPMxnAVmX0yyCz5mZ80zFbkYXcrqPnwlomuriiivWfW6qRqYHZFxf+6xjodr1M7BgM6+5Ngp8wEeGDSgbE2fq2EVgT3wwNC5Cyr/ruGSgQmdusEBY1NrXJ9cXg0LvtCb2QlZjmY7JAY1fgmPQmNvoZm6zzoRZFB7K3zuiBXTJfxxlMLrMt5sXjeN/KFvDa/q5JXCKUD58MQikbVk1D4gW0Ta37Q9g5GshnS4jcmRY2CHulJ5IWwGXPicql4t9cPT9g1P90T4DrtevW4mHpkGwi0FdbEOgO2S6poCFYCoCx+Q11xUBchKo4n9VgNGHBulAAAAAAAAAAAAAAABAAAAATAAAAAIAAAABHVzZXIAAAAAWBEo2QAAAAD0hseAAAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAARcAAAAHc3NoLXJzYQAAAAMBAAEAAAEBAOySy/JuLGJEpXH2E7dieK8eGABFRTHICDYW4qW9MBAuLjMKMEbdo6Liro5bdzRvLJYS542M8aNSiAILuru4f5SphIMC7FJCcTJzROw/4v2R+XvFXa1MXWlOWXEBw3jAGC3exyAxMETc4bqy2kBneCy8/WdSR1usgZhd4zr4x1qRjFPpYPtPzSJtOdjen4pK7La9Bb8PAvrJqn2tBr790VP4FMHRsElY/AWOmrNuOmyiAAmnxYMIstn8MM2I8E9UCaRwtBvzvEdWjae+U+8U/E/hZX35IHoha7nE6NDi1i+lNupuxOaOe3fFRgJRo6LBsdcwILlOcqDnEfL06tqWUCMAAAEPAAAAB3NzaC1yc2EAAAEA5VgoEJlzUtsFwFMRW+CwxDagl4HvspwIyOn2ntPnpCqR1p+fdfzd3OZNrLMb/8wJU1SZzhJjseA2h+D21PrDrcNJ5xKAee3v5EmCVvGZE5IexEvaAJYFcPSfd8IU8lby7RGJ014H0j0+15epnVInoQfq9syw1okxIt4RONXq59m/s+cKZblP56lKgauFp78hZcY00HGqfaI24MMnZnXqqoyN5q5Ax10yF8PzpAh/mrnxr5Uc2jcBmYvbdmF1A+rxKe0Efk9Si5WvX7djbCCf2KpkTzJFm5MBWf8Y+D6H184DRhGZeUpRZaK2HKwsXFOv+dnGYDTlnM785EAx0N1s7A==\n")},
		{"./testdata/id_ecdsa.user.pub", "test@example.com", []byte("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDipzfw6kJ3rVFWakgaWInk/gp0yOuT7EVf3i1hMWcfcAlyzXhp0D46IWCBTlkysnO51U6QXAKQdi4zstbKObhE=\n")},
		{"./testdata/id_ecdsa.user-cert.pub", "test@example.com", []byte("ecdsa-sha2-nistp256-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20AAAAg2kMuKoFT5GQkWlGaoHBvu6VFJXidMlK5XhHDCAhhGisAAAAIbmlzdHAyNTYAAABBBDipzfw6kJ3rVFWakgaWInk/gp0yOuT7EVf3i1hMWcfcAlyzXhp0D46IWCBTlkysnO51U6QXAKQdi4zstbKObhEAAAAAAAAAAAAAAAEAAAACSUQAAAAIAAAABHVzZXIAAAAAYU0z8AAAAAEdRVJDAAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAAGgAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAAhuaXN0cDI1NgAAAEEEOKnN/DqQnetUVZqSBpYieT+CnTI65PsRV/eLWExZx9wCXLNeGnQPjohYIFOWTKyc7nVTpBcApB2LjOy1so5uEQAAAGUAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAEoAAAAhAIlHBX35avjROyvKjjLNMDrgP3Wc6RdbS+W1MJMG3DhZAAAAIQD33z36SyNlikz/viMuBeTKHZP613DVSrK5vhoH57cBoQ==\n")},
	}
	for _, c := range cases {
		key, comment, err := GetPublicKeyFromFile(c.filename)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
		if !bytes.Equal(ssh.MarshalAuthorizedKey(key), c.key) {
			t.Errorf("expect public key %q, got %q", c.key, ssh.MarshalAuthorizedKey(key))
		}
		if comment != c.comment {
			t.Errorf("expect comment %q, got %q", c.comment, comment)
		}
	}
	_, _, err := GetPublicKeyFromFile("./testdata/non-exist")
	if !os.IsNotExist(err) {
		t.Errorf("expect \"no such file\", got %v", err)
	}
	_, _, err = GetPublicKeyFromFile("./testdata/empty")
	if err == nil || !strings.Contains(err.Error(), "keys not found") {
		t.Errorf("expect \"keys not found\", got %v", err)
	}
}

// TestGetPublicKeysFromFile tests GetPublicKeysFromFile to read the multiple pubkey from the public key file.
func TestGetPublicKeysFromFile(t *testing.T) {
	t.Parallel()
	cases := []struct {
		filename string
		comments []string
		keys     []string
	}{
		{
			"./testdata/id_rsa.multiple_keys.pub",
			[]string{"test@example.com", "test@example.com"},
			[]string{
				"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDsksvybixiRKVx9hO3YnivHhgARUUxyAg2FuKlvTAQLi4zCjBG3aOi4q6OW3c0byyWEueNjPGjUogCC7q7uH+UqYSDAuxSQnEyc0TsP+L9kfl7xV2tTF1pTllxAcN4wBgt3scgMTBE3OG6stpAZ3gsvP1nUkdbrIGYXeM6+MdakYxT6WD7T80ibTnY3p+KSuy2vQW/DwL6yap9rQa+/dFT+BTB0bBJWPwFjpqzbjpsogAJp8WDCLLZ/DDNiPBPVAmkcLQb87xHVo2nvlPvFPxP4WV9+SB6IWu5xOjQ4tYvpTbqbsTmjnt3xUYCUaOiwbHXMCC5TnKg5xHy9OrallAj\n",
				"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDNEWjcPtgb3A7amx/UhlBeSPMxnAVmX0yyCz5mZ80zFbkYXcrqPnwlomuriiivWfW6qRqYHZFxf+6xjodr1M7BgM6+5Ngp8wEeGDSgbE2fq2EVgT3wwNC5Cyr/ruGSgQmdusEBY1NrXJ9cXg0LvtCb2QlZjmY7JAY1fgmPQmNvoZm6zzoRZFB7K3zuiBXTJfxxlMLrMt5sXjeN/KFvDa/q5JXCKUD58MQikbVk1D4gW0Ta37Q9g5GshnS4jcmRY2CHulJ5IWwGXPicql4t9cPT9g1P90T4DrtevW4mHpkGwi0FdbEOgO2S6poCFYCoCx+Q11xUBchKo4n9VgNGHBul\n"},
		},
		{
			"./testdata/id_rsa.multiple_keys-cert.pub",
			[]string{"test@example.com", "test@example.com"},
			[]string{
				"ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgEvcafMLLBUsNGb8twj4FylpYp2l0fm306QXnEtkgBVcAAAADAQABAAABAQDy384j/9LHlVK+pEvYFAq+3lztOdsesWQAUl39UQnThx3TsyAXBL3NUS7hx4x/uD0R0J+XWz5t82c4zvVVeCg7RX6vWyNl7tEhRcaxwCIxZKct6J57+vFfE7xZA0D6KCjwzYlEj/755A3b299JwiBEW/RySkOtkMrJT79faUjaBk4Gv5f8OQEIp3neE2F9TKtsmosJ26hkKAq6+Qxz8GhMIMjFIW4LawPwqpKsCbCDvTdH6V/Ayi8rltnh5nPmGP6/tZpRpNM5h2CPBRVkbex9cWqVMY4DnITcweSZO6P05whvFpD1o/S2j05saMu+Z2Np8QiFMEqUKalaxzEeKADhAAAAAAAAAAAAAAACAAAAATAAAAAMAAAACGhvc3RuYW1lAAAAAFgRKMIAAAAA9IbHgAAAAAAAAAAAAAAAAAAAARcAAAAHc3NoLXJzYQAAAAMBAAEAAAEBAOySy/JuLGJEpXH2E7dieK8eGABFRTHICDYW4qW9MBAuLjMKMEbdo6Liro5bdzRvLJYS542M8aNSiAILuru4f5SphIMC7FJCcTJzROw/4v2R+XvFXa1MXWlOWXEBw3jAGC3exyAxMETc4bqy2kBneCy8/WdSR1usgZhd4zr4x1qRjFPpYPtPzSJtOdjen4pK7La9Bb8PAvrJqn2tBr790VP4FMHRsElY/AWOmrNuOmyiAAmnxYMIstn8MM2I8E9UCaRwtBvzvEdWjae+U+8U/E/hZX35IHoha7nE6NDi1i+lNupuxOaOe3fFRgJRo6LBsdcwILlOcqDnEfL06tqWUCMAAAEPAAAAB3NzaC1yc2EAAAEAH0If+zV0nAeafiV64LubIN34uf9PbwhuRS4K1mlFqIQkDit9WWfmY3OeJiC7S0Y8UoeETlKqu/4EQvHCmmiirGYGC6YRADSuEc3BDSasArn9rZ4OutoiVkWOEYNCsyyL41+CPxKNpVK4sI9NR/3uaFilHa9/8mFjyVIPWm0bMxKJvIQ3PMfi7JL4ifjexi3s6rnFLmiRpVA1mWh6Sh+6fIrgCcFGbFUtNdg9fzZvq9GJy1HYtvvDGXYlqTb9iaJhKueQiSdGUTzHtVr3fAcz6c2KHnSs7d0yQguYLVsccnWj+w8rk/e8GmiPa2t5gm20Q7FR7cBSG5L3vN9bACLcKQ==\n",
				"ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgbzrh1I5VTIwvyTmh0LhnV2hgotmGltvlBE6SC3SL+G0AAAADAQABAAABAQDNEWjcPtgb3A7amx/UhlBeSPMxnAVmX0yyCz5mZ80zFbkYXcrqPnwlomuriiivWfW6qRqYHZFxf+6xjodr1M7BgM6+5Ngp8wEeGDSgbE2fq2EVgT3wwNC5Cyr/ruGSgQmdusEBY1NrXJ9cXg0LvtCb2QlZjmY7JAY1fgmPQmNvoZm6zzoRZFB7K3zuiBXTJfxxlMLrMt5sXjeN/KFvDa/q5JXCKUD58MQikbVk1D4gW0Ta37Q9g5GshnS4jcmRY2CHulJ5IWwGXPicql4t9cPT9g1P90T4DrtevW4mHpkGwi0FdbEOgO2S6poCFYCoCx+Q11xUBchKo4n9VgNGHBulAAAAAAAAAAAAAAABAAAAATAAAAAIAAAABHVzZXIAAAAAWBEo2QAAAAD0hseAAAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAARcAAAAHc3NoLXJzYQAAAAMBAAEAAAEBAOySy/JuLGJEpXH2E7dieK8eGABFRTHICDYW4qW9MBAuLjMKMEbdo6Liro5bdzRvLJYS542M8aNSiAILuru4f5SphIMC7FJCcTJzROw/4v2R+XvFXa1MXWlOWXEBw3jAGC3exyAxMETc4bqy2kBneCy8/WdSR1usgZhd4zr4x1qRjFPpYPtPzSJtOdjen4pK7La9Bb8PAvrJqn2tBr790VP4FMHRsElY/AWOmrNuOmyiAAmnxYMIstn8MM2I8E9UCaRwtBvzvEdWjae+U+8U/E/hZX35IHoha7nE6NDi1i+lNupuxOaOe3fFRgJRo6LBsdcwILlOcqDnEfL06tqWUCMAAAEPAAAAB3NzaC1yc2EAAAEA5VgoEJlzUtsFwFMRW+CwxDagl4HvspwIyOn2ntPnpCqR1p+fdfzd3OZNrLMb/8wJU1SZzhJjseA2h+D21PrDrcNJ5xKAee3v5EmCVvGZE5IexEvaAJYFcPSfd8IU8lby7RGJ014H0j0+15epnVInoQfq9syw1okxIt4RONXq59m/s+cKZblP56lKgauFp78hZcY00HGqfaI24MMnZnXqqoyN5q5Ax10yF8PzpAh/mrnxr5Uc2jcBmYvbdmF1A+rxKe0Efk9Si5WvX7djbCCf2KpkTzJFm5MBWf8Y+D6H184DRhGZeUpRZaK2HKwsXFOv+dnGYDTlnM785EAx0N1s7A==\n"},
		},
	}
	for _, c := range cases {
		keys, comments, _ := GetPublicKeysFromFile(c.filename)
		for i := range keys {
			if !bytes.Equal(ssh.MarshalAuthorizedKey(keys[i]), []byte(c.keys[i])) {
				t.Errorf("expect public key %q, got %q", c.keys[i], ssh.MarshalAuthorizedKey(keys[i]))
			}
			if comments[i] != c.comments[i] {
				t.Errorf("expect comment %s, got %s", c.comments[i], comments[i])
			}
		}
	}
	_, _, err := GetPublicKeysFromFile("./keys/non-exist")
	if !os.IsNotExist(err) {
		t.Errorf("expect \"no such file\", got %v", err)
	}
	keys, _, _ := GetPublicKeysFromFile("./keys/id_rsaBROKEN.user.pub")
	if len(keys) != 0 {
		t.Errorf("expect 0 keys, got %v", len(keys))
	}
}

func TestCastSSHPublicKeyToAgentKey(t *testing.T) {
	t.Parallel()
	var blob = []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCZwcH+SWVmjO52EX2zOilBnTKexhEIHDyraFDlHW1n/Xsjgyuv6Ob+thK45oeqm0t32l+O2r6kFc5W2lMSXmQYIwgG45dFiuiNah4/2+ikHBd/ntGQgSuGm0ufL0N1XbPN8TUXJQrms3Xz+dVAh390M3AxkdBRy3Bd6AqJfEZMHtZwvT0/B3mqGswWUMtBGIAjdJ0RePN2Rh8KR970H2WYF/E+T0tExhK9ntsF8vkFe7EBkRwTivwrh9EsQKT0Kjy2KpuUN+x+A5Hm1aklhHf91fadJHR6MInLcCXPR0t1rKfJWYLOu+QlZ80bEmmyfNFjbhnC559MZItj7k2AUSMx")
	key, _, _, _, err := ssh.ParseAuthorizedKey(blob)
	if err != nil {
		t.Fatal(err)
	}
	agentkey := CastSSHPublicKeyToAgentKey(key)
	if string(blob) != agentkey.String() {
		t.Errorf("expect %v, got %v", string(blob), agentkey.String())
	}

	agentkey = &agent.Key{
		Format: "fake-cert",
		Blob:   []byte("blob"),
	}
	key = CastSSHPublicKeyToAgentKey(agentkey)
	if !reflect.DeepEqual(agentkey, key) {
		t.Fatalf("expect to have same keys, got %v and %v", agentkey, key)
	}
}

func TestCastSSHPublicKeyToCertificate(t *testing.T) {
	t.Parallel()
	agentkey := &agent.Key{
		Format: "fake-cert",
		Blob:   []byte("blob"),
	}
	_, err := CastSSHPublicKeyToCertificate(agentkey)
	if err == nil {
		t.Fatal("CastSSHPublicKeyToCertificate should fail to parse fake certificate successfully")
	}

	var blob = []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCZwcH+SWVmjO52EX2zOilBnTKexhEIHDyraFDlHW1n/Xsjgyuv6Ob+thK45oeqm0t32l+O2r6kFc5W2lMSXmQYIwgG45dFiuiNah4/2+ikHBd/ntGQgSuGm0ufL0N1XbPN8TUXJQrms3Xz+dVAh390M3AxkdBRy3Bd6AqJfEZMHtZwvT0/B3mqGswWUMtBGIAjdJ0RePN2Rh8KR970H2WYF/E+T0tExhK9ntsF8vkFe7EBkRwTivwrh9EsQKT0Kjy2KpuUN+x+A5Hm1aklhHf91fadJHR6MInLcCXPR0t1rKfJWYLOu+QlZ80bEmmyfNFjbhnC559MZItj7k2AUSMx")
	key, _, _, _, err := ssh.ParseAuthorizedKey(blob)
	if err != nil {
		t.Fatal(err)
	}
	_, err = CastSSHPublicKeyToCertificate(key)
	if err == nil {
		t.Fatal("CastSSHPublicKeyToCertificate should fail to parse regular public key")
	}

	blob = []byte("ssh-rsa-cert-v01@openssh.com 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")
	key, _, _, _, err = ssh.ParseAuthorizedKey(blob)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := CastSSHPublicKeyToCertificate(key)
	if err != nil {
		t.Fatalf("CastSSHPublicKeyToCertificate failed to parse cert, err: %v", err)
	}
	if !bytes.Equal(key.Marshal(), cert.Marshal()) {
		t.Errorf("expect %v, got %v", key.Marshal(), cert.Marshal())
	}
	cert, err = CastSSHPublicKeyToCertificate(CastSSHPublicKeyToAgentKey(key))
	if err != nil {
		t.Fatalf("CastSSHPublicKeyToCertificate failed to parse agent key, err: %v", err)
	}
	if !bytes.Equal(key.Marshal(), cert.Marshal()) {
		t.Errorf("expect %v, got %v", key.Marshal(), cert.Marshal())
	}
}
