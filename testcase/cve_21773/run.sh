#!/bin/bash

sudo ./apache2.4.49/bin/httpd
pids=$(pgrep httpd)
port=9953
for pid in $pids
do 
    echo $pid
    sudo gdbserver --attach :$port $pid &
    python3 ../../src/entry.py -c command.txt -b httpd -p $port --pid $pid &
    let "port++"
done 
