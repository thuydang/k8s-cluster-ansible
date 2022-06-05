#!/bin/bash

# Script is needed because my default firewall rules are messed up and after
# every restart, docker containers can't make connections to the host, notably
# preventing debuggers like xdebug from attaching.

set -euo pipefail

# Unless docker is stopped with no containers running, docker will leave zombie
# proxy processes that hold the ports open preventing the start of new containers.
# If this happens I have to kill them manually: https://stackoverflow.com/a/61239636/3779

if [ ! $(docker ps | wc -l) == "1" ]; then
  echo "Some docker containers are running."
  exit 0
fi


sudo service docker stop

sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -t nat -F
sudo iptables -t mangle -F
sudo iptables -F
sudo iptables -X

sudo service docker start