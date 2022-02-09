#!/bin/sh
cd ../../debugger
#cd ../../load_shellcode
total=0
for i in $(seq 1 100)
do
    echo $i
    start=$(date +"%s%N") #milliseconds
    start=$((start/1000000))
    echo $start
    ./bp_manual ../test_case/complex/complex < ../test_case/complex/bp_data
    #python solve.py
    end=$(date +"%s%N") #milliseconds
    end=$(( end/1000000 ))
    bias=$(( end-start ))
    total=$(( total+bias ))
done
echo $(( total/100 ))