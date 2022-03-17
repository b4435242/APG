#!/bin/bash

binary=branch_function
start="0x4004eb"
target="0x400508"
python3 ../../partial_symbolic.py $binary $start $target