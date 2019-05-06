#!/bin/bash
dest=server1
user=$(whoami)
cd | exit 1
for file in "$@" ; do
	rsync -aHPvz "${user}@${dest}:./${file}" "./${file}"
done