# YSSHRA 
YSSHRA is the registration authority of YSSHCA (Yahoo SSHCA).

>
> A service to authenticate the client and provision ephemeral SSH user certificate.
> Note: **Features for attestation check during authentication, yubikey based touch-to-login and touch-to-sudo are coming up next.**

[Crypki](https://github.com/theparanoids/crypki) can be used as the CA signing backend of the service.

## Table of Contents

- [Install](#install)
- [Configuration](#configuration)
- [Usage](#usage)
- [Contribute](#contribute)
- [License](#license)

## Install

This installation guide assumes the use of [Crypki](https://github.com/theparanoids/crypki) as the signing backend.

**Disclaimer:** The following guidelines are to help you to get started with YSSHCA;
> they should be used only for testing/development purposes.


### 1. Add authorized users

* Add your username into `docker/ysshra/user_allowlist.txt`.

### 2. Build ysshra docker image

```bash
docker build -f ./docker/Dockerfile -t ysshra-local .
```

Password authentication is disabled (`PermitEmptyPasswords yes`, `AuthenticationMethods none`) in sshd config file
at `docker/ysshra/ssh/sshd_config.ysshra`. You can customize it or pull in PAM modules for your own environments.

### 3. Generate host certificates and user keys

```bash
pushd ./docker

# Generate sshd host certificates.
./gen-ssh-crt.sh

# Generate ssh user keys.
./gen-user-key.sh ./ysshra/user_allowlist.txt

popd
```

### 4. Setup CA signing backend (Crypki)

Please refer to the section `Install` in [Crypki readme](https://github.com/theparanoids/crypki).

Copy `ca.crt` `client.crt` and `client.key` to the folder `docker/tls-crt` in this repo.

```bash
CRYPKI_CRT_PATH=${PATH_TO_CRYPKI_REPO}/docker-softhsm/tls-crt

mkdir -p ./docker/tls-crt
cp ${CRYPKI_CRT_PATH}/ca.crt ${CRYPKI_CRT_PATH}/client.crt ${CRYPKI_CRT_PATH}/client.key ./docker/tls-crt
```

Note: **These steps configure Crypki to use SoftHSM. For production setup, a physical HSM or cloud HSM should be used.**

### 5. Run ysshra container

```bash
pushd ./docker

docker run -d -p :222:222 -v $PWD/log:/var/log/ysshra -v $PWD/tls-crt:/opt/ysshra/tls-crt:ro \
-v $PWD/ssh-crt:/opt/ysshra/ssh-crt:ro -v $PWD/config.sample.json:/opt/ysshra/config.json \
-v $PWD/ssh-user:/etc/ssh/authorized_public_keys/ \
--rm --name ysshra -h "localhost" ysshra-local 

# setup network for ysshra container and crypki container. 
docker network create pki
docker network connect pki ysshra
docker network connect pki crypki

popd
```

### 6. Verify the YSSHRA server is up and running

```bash
$telnet localhost 222 
Trying ::1...
Connected to localhost.
Escape character is '^]'.
SSH-2.0-OpenSSH_8.9p1 Debian-3
```

You may then refer to [the regular-cert steps](#certificate-type-regular) to request a user certificate from the YSSHRA container.

## Configuration

We include a valid gensign configuration file [here](config.sample.json) in the YSSHRA docker.

Some default values are also provided in [`config.go`](go/config/config.go).

## Usage

### SSH Certificate

YSSHCA utilizes [Go SSH library](https://pkg.go.dev/golang.org/x/crypto/ssh) to generate SSH certificates and CSRs, which conforms to the format defined in [OpenSSH](https://www.openssh.com/specs.html).  
YSSHCA defines an extensible key ID format for user certificates, and uses it to identify the types and usages of SSH certificates for different PAM modules.

The `Key ID` field in a SSH certificate is typically used to identify in human-readable form the specific certificate signing key (potentially stored in an HSM), the specific user key wrapped by the certificate, or both.
However, YSSHCA `Key ID` is in JSON format, which enables gensign and different CSR handlers (or modules) to fill detailed information into CSR and certificates.
Compared to other certificate attributes (e.g. critical options), `Key ID` can be logged in OpenSSH during SSH handshake and in YSSHRA gensign easily.

Following is a regular SSH certificate generated by YSSHRA. The certificate principals (`prins`), transaction ID (`transID`),
request user (`reqUser`), request IP (`reqIP`), request host (`reqHost`) and Key ID version (`ver`) can be found in the parsed certificate.

```
Type: ssh-rsa-cert-v01@openssh.com user certificate
Public key: RSA-CERT SHA256:psiQqqfGzADw4NR83WeJgTbnZ5oOlqbnC3ggncdGHHI
Signing CA: RSA SHA256:mho4TPD8zXYmXT1Zx5EelKi4imBjwgyIBqYTm9X9YB0 (using rsa-sha2-256)
Key ID: "{"prins":["user_a"],"transID":"15537d7b63","reqUser":"user_a","reqIP":"172.17.0.1","reqHost":"localhost","isFirefighter":false,"isHWKey":false,"isHeadless":false,"isNonce":false,"usage":0,"touchPolicy":1,"ver":1}"
...
```

Other fields are defined as follows:

|               | Type        | Meaning                                                                         | Values                                     | Remark                                                                                             |
|---------------|-------------|---------------------------------------------------------------------------------|--------------------------------------------|----------------------------------------------------------------------------------------------------|
| isFirefighter | Bool        | Whether the cert is for emergency situation                                     | True/False                                 | Firefighter certs usually have longer validity (e.g. 30 days) for emergency situation.             |
| isHWKey       | Bool        | Whether the private key of the cert is backed in a hardware (e.g. yubikey, HSM) | True/False                                 | Usually a hardware certificate requires a touch (or a 2nd authN) during challenge response.        |
| isHeadless    | Bool        | Whether the cert is provisioned for headless user (CICD tools)                  | True/False                                 | Usually a headless certificate doesn't require a touch (or a 2nd authN) during challenge response. |
| isNonce       | Bool        | Whether the cert is a short living one-time authN password                      | True/False                                 |                                                                                                    |
| usage         | Enum (uint) | Usage limitation on the certificate                                             | 0: all usage; 1: SSH only                  |                                                                                                    |
| touchPolicy   | Enum (uint) | Indicate whether the cert require a touch or not during challenge response.     | 0: Default; 1: Never; 2: Always; 3: Cached |                                                                                                    |                                                                            |                  |                                                                                             |

### Certificate Type

YSSHRA declares [Handler](./gensign/handler.go) interface to define the behaviors that handle users' SSH certificate requests.
A handler generate various types of CSRs for a particular scenario usage.
The handler can be configured in gensign config path (`/opt/ysshra/config.json`).

### Certificate Type: Regular

YSSHRA provides [Regular Handler](./gensign/regular) to generate regular CSRs for a non-yubikey scenario.
That is, a user presents the regular certificate to a SSH/SUDO PAM module.
Then the module authenticate the user by key challenge against the priv key in the user's SSH agent without a touch.
The key ID fields of a regular certificate are shown as follows:

|               | Value           |
|---------------|-----------------|
| isFirefighter | F               |
| isHWKey       | F               |
| isHeadless    | F               |
| isNonce       | F               |
| usage         | 0 (All Usages)  |
| touchPolicy   | 1 (Never Touch) |

#### Request a regular user certificate from the ysshra container

Note: `user_a` exists in `docker/ysshra/user_allowlist.txt`, and the corresponding linux user was created in ysshra container during the docker build.

* Add `user_a`'s private key to the ssh-agent

```bash
ssh-add -K ./docker/ssh-user/user_a
```

* ssh against the ysshra container

```bash
ssh -A user_a@localhost -p 222 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
'{"ifVer":7, "username":"user_a", "hostname":"localhost", "sshClientVersion":"0.0"}'
```

Note: You may encounter `The authenticity of host '[localhost]:222 ([::1]:222)' can't be established` error
when performing SSH against localhost without options `-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no`.
To get rid of it, please append the CA public key  `./docker/ssh-crt/host_ca_key.pub` to your known host file `~/.ssh/known_hosts`.

```bash
echo "@cert-authority *" $(cat ./docker/ssh-crt/host_ca_key.pub) >> ~/.ssh/known_hosts
 
ssh -A user_a@localhost -p 222 '{"ifVer":7, "username":"user_a", "hostname":"localhost", "sshClientVersion":"0.0"}'
```

* Check the requested certificate

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
## Contribute

Please refer to [Contributing.md](Contributing.md) for information about how to get involved.
We welcome issues, questions, and pull requests.

## License

This project is licensed under the terms of the [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0) open source license. Please refer to [LICENSE](LICENSE) for the full terms.
