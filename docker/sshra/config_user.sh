#!/bin/bash
set -euo pipefail

allowlist_filepath=$1
while read -r line; do
  # Remove leading and trailing spaces.
  USER=${line// }
  # Ref: https://unix.stackexchange.com/a/193131/311426
  # Set empty password to grant user SSH access without passwords.
  # Note: `PermitEmptyPasswords yes` is set in sshd config.
  if [[ -n ${USER} ]]; then
    echo "Create user ${USER} in the docker container..."
    useradd -m "${USER}"
    usermod -p '' "${USER}"
  fi
done < "${allowlist_filepath}"
