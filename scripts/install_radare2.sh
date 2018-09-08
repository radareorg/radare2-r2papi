#!/bin/sh

cd /tmp
wget https://github.com/radare/radare2/archive/master.zip
unzip master.zip
rm -fr master.zip
cd radare2-master
sys/install.sh
