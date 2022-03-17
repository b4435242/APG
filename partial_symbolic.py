import angr
import claripy
import time
import os
import sys
from angr import sim_options as so

def find_symbolic_buffer(state):
    # TO BE MODIFIED
    # get_variables() ->skip file currently
    # addrs_for_name()
    sym_vars = { #mem: [(addr, len), (addr, len)]
        'reg':[], 
        'mem':[],
        'file':[]
        }
    for key, symbol in state.solver.get_variables():
        sym_vars[key[0]].append((key[1], symbol.length))
        print(key[0], state.solver.eval(symbol, cast_to=bytes))

    print(sym_vars)
    return sym_vars
        

def main(argv):
    
    binary = argv[1]
    start_addr = int(argv[2],16)
    target_addr = int(argv[3],16)
    
    proj = angr.Project(binary)
    extras = {
        so.REVERSE_MEMORY_NAME_MAP, # save symbol to memory address
        so.TRACK_ACTION_HISTORY
    }
    state = proj.factory.call_state(addr=start_addr, add_options=extras)
    sm = proj.factory.simulation_manager(state)

    state.regs.rbp=0x7fffffffdb80
    state.regs.rsp=0x7fffffffdaa0
    
    sm = sm.explore(find=target_addr)

    if (len(sm.found)>0):
        state = sm.found[0]
        print(state)
        find_symbolic_buffer(state)
        #for addr in find_symbolic_buffer(state):
        #    print(addr)

if __name__ == "__main__":
    
    before = time.time()
    main(sys.argv)
    after = time.time()
    print("Time elapsed: {}".format(after - before))