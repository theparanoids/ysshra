// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package message

import "errors"

func (a *Attributes) sanityCheck() error {
	if a.SSHClientVersion == "" {
		return errors.New("ssh client version cannot be empty")
	}
	if a.Username == "" {
		return errors.New("user name cannot be empty")
	}
	if a.Hostname == "" {
		return errors.New("host name cannot be empty")
	}
	return nil
}

func (a *Attributes) populate() {
	if a.TouchlessSudo == nil {
		a.TouchlessSudo = &TouchlessSudo{}
	}
}
