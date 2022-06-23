#!/bin/bash
#./toy_nopie
pid=$(pgrep toy_nopie)
port=9953
sudo gdbserver --attach :$port $pid &
python3 ../../src/entry.py -c nopie_c.txt -b toy_nopie -p $port --pid $pid
#python3 symbion.py toy_nopie 0x29a 0x1c0 