# Copyright 2022 Yahoo Inc.
# Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

FROM golang:1.20
ENV YSSHRA_DIR /go/src/github.com/theparanoids/ysshra
COPY . ${YSSHRA_DIR}
WORKDIR ${YSSHRA_DIR}
RUN go get -v ./... && go build -o ${YSSHRA_DIR}/bin/gensign ${YSSHRA_DIR}/cmd/gensign

FROM debian:sid-slim
ENV YSSHRA_DIR /go/src/github.com/theparanoids/ysshra
WORKDIR /opt/ysshra

RUN apt-get update && \
    apt-get -y install openssh-server \
    openssl \
    openssh-client \
    # lsb-base for init functions
    lsb-base \
    vim

COPY --from=0 ${YSSHRA_DIR}/bin/gensign /usr/bin/gensign
COPY docker/ysshra/init.d/ysshra /etc/init.d/ysshra
COPY docker/ysshra/ssh/sshd_config.ysshra /etc/ssh/sshd_config.ysshra
COPY docker/ysshra/config_user.sh /tmp/config_user.sh
COPY docker/ysshra/user_allowlist.txt /tmp/user_allowlist.txt

# Create linux users in the container.
RUN /tmp/config_user.sh /tmp/user_allowlist.txt

CMD ["/etc/init.d/ysshra", "start"]
