#!/bin/bash
dest=server1
user=$(whoami)
cd || exit 1
rsync "${user}@${dest}:." | more