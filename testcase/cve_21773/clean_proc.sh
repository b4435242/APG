#!/bin/bash

pids_h=$(pgrep httpd)
pids_g=$(pgrep gdbserver)

for pid in $pids_g
do 
    echo $pid
    sudo kill $pid
done

for pid in $pids_h
do 
    echo $pid
    sudo kill $pid
done