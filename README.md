# APG

### example

1. testcase/toy_server/toy_server 
2. sudo gdbserver --attach :9953 $(pidof toy_server)
3. python3 src/entry.py -b testcase/toy_server/toy_server -c testcase/toy_server/config.txt