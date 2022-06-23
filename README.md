# APG

### example

1. testcase/toy_server/toy_server 
2. sudo gdbserver --attach :9953 $(pidof toy_server)
3. python3 src/entry.py -b testcase/toy_server/toy_server -c testcase/toy_server/config.txt


### params.txt setup
breakpoint $addr
target $addr
sp $n_pointer $size $sp_offset_0 $val_offset_0 $sp_offset_1 $val_offset_1 ... $sp_offset_${n_pointer} $val_offset_${n_pointer} 