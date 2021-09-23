package main

import (
	"log"
	"os"

	"go.vzbuilders.com/peng/sshra-oss/agent/ssh"
	"go.vzbuilders.com/peng/sshra-oss/config"
	"go.vzbuilders.com/peng/sshra-oss/csr"
	"go.vzbuilders.com/peng/sshra-oss/gensign"
	"go.vzbuilders.com/peng/sshra-oss/gensign/regular"
	"go.vzbuilders.com/peng/sshra-oss/internal/cert/signer"
)

// TODO: specify a config path.
const confPath = ""

func main() {
	conf, err := config.NewGensignConfig(confPath)
	if err != nil {
		log.Fatalf("failed to load gensign configuration, %v", err)
	}
	// TODO: Setup mutli-writer for info and debug loggers.

	conn, err := ssh.AgentConn()
	if err != nil {
		log.Fatalf("failed to initailize the connection for ssh agent, %v", err)
	}

	handlers := []gensign.Handler{
		regular.NewHandler(conf, conn),
	}

	// SSH_ORIGINAL_COMMAND is set by OpenSSH when a ForceCommand directive is matched in a sshd configuration file.
	// We use it as a convenient way to let an SSH session pass parameters to an SSH server.
	reqParam, err := csr.NewReqParam(os.Getenv("SSH_ORIGINAL_COMMAND"))
	if err != nil {
		log.Fatalf("failed to load parameters from the ssh original command, %v", err)
	}

	if err := gensign.Run(reqParam, handlers, signer.NewCrypkiSigner(conf)); err != nil {
		log.Fatal(err)
	}
}
