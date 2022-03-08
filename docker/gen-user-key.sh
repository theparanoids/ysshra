#! /usr/bin/env bash
set -euo pipefail

mkdir -p ./ssh-user

allowlist_filepath=$1
while read -r line; do
  # Remove leading and trailing spaces.
  USER=${line// }
  if [[ -n ${USER} ]]; then
    echo "Generating ssh user key for ${USER} ..."
    ssh-keygen -N "" -b 384 -t ecdsa -f "./ssh-user/${USER}"
  fi
done < "${allowlist_filepath}"
