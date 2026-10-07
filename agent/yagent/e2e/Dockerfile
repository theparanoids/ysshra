# Copyright 2026 Yahoo Inc.
# Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

# Debian trixie ships OpenSSH 10.0, new enough for associated-certs (9.6+).
FROM golang:1.25-trixie

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client softhsm2 opensc \
 && rm -rf /var/lib/apt/lists/*
