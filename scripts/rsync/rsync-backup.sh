#!/bin/bash
export RSYNC_RSH=/usr/bin/ssh
dest=baskup1
user=$(whoami)
cd || exit 1
rsync -aHPvz . "${user}@$dest}:."