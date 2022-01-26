import angr
import claripy
import time
import os
import sys

def find_symbolic_buffer(state):
    # TO BE MODIFIED
    # get_variables()
    # addrs_for_name()
    stdin = state.posix.stdin

    sym_addrs = [ ]
    for _, symbol in state.solver.get_variables('file', stdin.ident):
        sym_addrs.extend(state.memory.addrs_for_name(next(iter(symbol.variables))))

    for addr in sym_addrs:
        yield addr

def main(argv):
    
    #binary = os.path.join("testcase", os.path.join("password", "password"))
    binary = argv[1]
    start_addr = argv[2]
    target_addr = argv[3]

    proj = angr.Project(binary)
    state = proj.factory.blank_state(addr=start_addr)
    sm = proj.factory.simulation_manager(state)
    
    sm = sm.explore(find=target_addr)

    if (len(sm.found)>0):
        state = sm.found[0]
        for addr in find_symbolic_buffer(state):
            print(addr)

if __name__ == "__main__":
    if len(sys.argv) == 4:
        sys.exit(main(sys.argv[1]))
    else:
        print("%s: <binary> <start_addr> <target_addr>" % sys.argv[0])

    before = time.time()
    print(main(sys.argv))
    after = time.time()
    print("Time elapsed: {}".format(after - before))