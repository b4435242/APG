import subprocess
import os
import nose
import avatar2 
import sys
import time

import angr
import claripy
from angr_targets import AvatarGDBConcreteTarget
from angr_zelos_target import ZelosConcreteTarget


GDB_SERVER_IP = '127.0.0.1'
GDB_SERVER_PORT = 9953

def main(argv):
    
    binary = argv[1]
    start_addr = int(argv[2],16)
    target_addr = int(argv[3],16)


    
    # Instantiation of the AvatarGDBConcreteTarget
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64,
                                        GDB_SERVER_IP, GDB_SERVER_PORT)
    


    # Creation of the project with the new attributes 'concrete_target'
    proj = angr.Project(binary, concrete_target=avatar_gdb, main_opts={'base_addr': 0x100000})

    proj.concrete_target.set_breakpoint(start_addr)

    while True:
        
        proj.concrete_target.run()

        state = proj.factory.entry_state(addr=start_addr)
        state.concrete.sync()
        sm = proj.factory.simulation_manager(state)

        state.options.add(angr.options.SYMBION_SYNC_CLE)
        state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)

        

        # Declaring a symbolic buffer
        arg0 = claripy.BVS('arg0', 32)

        # The address of the symbolic buffer would be the one of the
        # hardcoded malware configuration
        symbolic_buffer_address = state.regs.rbp-0x74
        print(state.regs.rbp)
        # Setting the symbolic buffer in memory!
        state.memory.store(symbolic_buffer_address, arg0)


        # Symbolically explore the malware to find a specific behavior by avoiding
        # evasive behaviors
        exploration = sm.explore(find=target_addr)
        # Get our synchronized state back!
        state = exploration.stashes['found'][0]
        solved_arg0 = state.solver.eval(arg0, cast_to=bytes)
        print(solved_arg0)
        addr = state.solver.eval(symbolic_buffer_address)
        print(addr)
        proj.concrete_target.write_memory(addr, solved_arg0)

    

if __name__ == "__main__":
    main(sys.argv)
