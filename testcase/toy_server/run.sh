#!/bin/bash
#./toy_server
pid=$(pgrep toy_server)
port=9953
sudo gdbserver --attach :$port $pid &
python3 ../../src/entry.py -c command.txt -b toy_server -p $port --pid $pid