# sshra-oss
The open-source repo for SSHRA and SSHRA-client

> An SSH service to authenticate the clients and to accept requests for SSH certificates.
> It performs key challenge and attestation against the client, and makes the request against CA (Certificate Authority).

[Crypki](https://github.com/theparanoids/crypki) can be used as the CA signing backend of the service.

# Update Notes
Features for yubikey touch-to-login and touch-to-sudo is coming up next.

* Provided [regular](./gensign/regular) handler to generate touchless SSH certificates CSR. 

# User Guide

## Installation

This guide takes [Crypki](https://github.com/theparanoids/crypki) as signing backend. 
The password authentication is disabled (`PermitEmptyPasswords yes`, `AuthenticationMethods none`) in sshd config file 
at `docker/RA/ssh/sshd_config.sshra`. Please feel free to adjust it or pull in PAM modules for your own environments.

### 1. Add authorized users

* Add your username into `docker/RA/user_allowlist.txt`.

### 2. Build sshra docker image

```bash
docker build -f ./docker/Dockerfile -t sshra-local .
```

### 3. Generate credentials 

```bash
pushd ./docker

# Generate sshd host certificates.
./gen-ssh-crt.sh

# Generate ssh user keys.
./gen-user-key.sh ./RA/user_allowlist.txt

popd
```

### 4. Setup CA signing backend (Cripki)

Please refer to the section `Install` in [Crypki](https://github.com/theparanoids/crypki) readme.

Then copy `ca.crt` `client.crt` and `client.key` to the folder `docker/tls-crt` in this repo.

```bash
CRYPKI_CRT_PATH=${PATH_TO_CRYPKI_REPO}/docker-softhsm/tls-crt

mkdir -p ./docker/tls-crt
cp ${CRYPKI_CRT_PATH}/ca.crt ${CRYPKI_CRT_PATH}/client.crt ${CRYPKI_CRT_PATH}/client.key ./docker/tls-crt
```

### 5. Run sshra container

```bash
pushd ./docker

docker run -d -p :222:222 -v $PWD/log:/var/log/sshra -v $PWD/tls-crt:/opt/sshra/tls-crt:ro \
-v $PWD/ssh-crt:/opt/sshra/ssh-crt:ro -v $PWD/config.sample.json:/opt/sshra/config.json \
-v $PWD/ssh-user:/etc/ssh/authorized_public_keys/ \
--rm --name sshra -h "localhost" sshra-local 

# setup network for sshra container and crypki container. 
docker network create pki
docker network connect pki sshra
docker network connect pki crypki

popd
```

## usage

### Use case: request a user certificate (touchless) from local

Note: `user_a` exists in `docker/RA/user_allowlist.txt`, and the corresponding linux user was created in sshra container during the docker build.   

* Add private key to the ssh-agent

```bash
ssh-add -K ./docker/ssh-user/user_a
```

* ssh against the sshra container

```bash
ssh -A user_a@localhost -p 222 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
'{"ifVer":7, "username":"user_a", "hostname":"localhost", "sshClientVersion":"0.0"}'
```

* Check the requsted certificate

```bash
$ssh-keygen -Lf <(ssh-add -L)
...
/dev/fd/63:14:
        Type: ssh-rsa-cert-v01@openssh.com user certificate
        Public key: RSA-CERT SHA256:psiQqqfGzADw4NR83WeJgTbnZ5oOlqbnC3ggncdGHHI
        Signing CA: RSA SHA256:mho4TPD8zXYmXT1Zx5EelKi4imBjwgyIBqYTm9X9YB0 (using rsa-sha2-256)
        Key ID: "{"prins":["user_a"],"transID":"15537d7b63","reqUser":"user_a","reqIP":"172.17.0.1","reqHost":"localhost","isFirefighter":false,"isHWKey":false,"isHeadless":false,"isNonce":false,"usage":0,"touchPolicy":1,"ver":1}"
        Serial: 0
        Valid: from 2022-03-03T17:31:48 to 2022-03-04T06:31:48
        Principals: 
                user_a
        Critical Options: (none)
        Extensions: 
                permit-X11-forwarding
                permit-agent-forwarding
                permit-port-forwarding
                permit-pty
                permit-user-rc
```
