#! /bin/sh
killall apt-get
apt update
killall apt-get
apt upgrade
apt install libopenscap8 