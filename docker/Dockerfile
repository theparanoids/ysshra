FROM golang:1.17.7
ENV SSHRA_DIR /go/src/github.com/theparanoids/sshra
COPY . ${SSHRA_DIR}
WORKDIR ${SSHRA_DIR}
RUN go get -v ./... && go build -o ${SSHRA_DIR}/bin/gensign ${SSHRA_DIR}/cmd/gensign

FROM debian:sid-slim
ENV SSHRA_DIR /go/src/github.com/theparanoids/sshra
WORKDIR /opt/sshra

RUN apt-get update && \
    apt-get -y install openssh-server \
    openssl \
    openssh-client \
    # lsb-base for init functions
    lsb-base \
    vim

COPY --from=0 ${SSHRA_DIR}/bin/gensign /usr/bin/gensign
COPY docker/sshra/init.d/sshra /etc/init.d/sshra
COPY docker/sshra/ssh/sshd_config.sshra /etc/ssh/sshd_config.sshra
COPY docker/sshra/config_user.sh /tmp/config_user.sh
COPY docker/sshra/user_allowlist.txt /tmp/user_allowlist.txt

# Create linux users in the container.
RUN /tmp/config_user.sh /tmp/user_allowlist.txt

CMD ["/etc/init.d/sshra", "start"]
