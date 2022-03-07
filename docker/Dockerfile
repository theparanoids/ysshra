FROM golang:1.17.7
ENV SSHRA_DIR /go/src/github.com/theparanoids/sshra
COPY . ${SSHRA_DIR}
WORKDIR ${SSHRA_DIR}
RUN go get -v ./... && go build -o ${SSHRA_DIR}/bin/gensign ${SSHRA_DIR}/cmd/gensign

FROM debian:sid-slim
ENV SSHRA_DIR /go/src/github.com/theparanoids/sshra
WORKDIR /opt/sshra

RUN apt-get update
RUN apt-get -y install openssh-server \
    openssl \
    openssh-client \
    rsyslog \
    sudo \
    # lsb-base for init functions
    lsb-base \
    vim

COPY --from=0 ${SSHRA_DIR}/bin/gensign /usr/bin/gensign
COPY docker/RA/init.d/sshra /etc/init.d/sshra
COPY docker/RA/ssh/sshd_config.sshra /etc/ssh/sshd_config.sshra
COPY docker/RA/config_user.sh /tmp/config_user.sh
COPY docker/RA/user_allowlist.txt /tmp/user_allowlist.txt

# Create linux users in the container.
RUN /tmp/config_user.sh /tmp/user_allowlist.txt

CMD ["/etc/init.d/sshra", "start"]
