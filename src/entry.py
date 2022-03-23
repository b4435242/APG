from distutils.command.config import config
import subprocess
import avatar2 
import time

import angr
import claripy
from angr_targets import AvatarGDBConcreteTarget
import argparse

GDB_SERVER_IP = '127.0.0.1'
GDB_SERVER_PORT = 9953

def parse_config(path): # support parsing only one set of breakpoint-target
    config = {
        "breakpoint":[],
        "target":[],
        "stack":[], # offset
        "heap":[], # not considered yet
        "data":[], # not considered yet
    }
    f = open(path)
    for line in f.readlines():
        splits = line.split()
        cmd, addr, size = splits[0], int(splits[1], 16), int(splits[-1], 16) # if cmd is mem, size is valid
        if addr!=size: # case of memory variable
            config[cmd].append((addr, size))
        else: # case of breakpoint and target
            config[cmd].append(addr)
    f.close()
    return config

def parse_arg():
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--binary", dest="binary")
    parser.add_argument("-c", "--config", dest="config")
    parser.add_argument("-d", "--debug", action="store_true")
    args = parser.parse_args()
    return args

def symbolic(args):
    binary = args.binary
    config = parse_config(args.config)
    __DEBUG__ = args.debug


    if __DEBUG__:
        subprocess.Popen("gdbserver %s:%s %s" % (GDB_SERVER_IP,GDB_SERVER_PORT,binary),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=True)

    # Instantiation of the AvatarGDBConcreteTarget
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64,
                                        GDB_SERVER_IP, GDB_SERVER_PORT)
    
    # Creation of the project with the new attributes 'concrete_target'
    proj = angr.Project(binary, concrete_target=avatar_gdb)
    breakpoint = config["breakpoint"][0]
    target = config["target"][0]



    proj.concrete_target.set_breakpoint(breakpoint)

    while True:
        
        proj.concrete_target.run() # continue until breakpoint

        state = proj.factory.entry_state(addr=breakpoint) # start symbolic execution from breakpoint
        state.concrete.sync() # sync state from running process through gdbserver
        sm = proj.factory.simulation_manager(state)

        state.options.add(angr.options.SYMBION_SYNC_CLE)
        state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)

        
        # setup symbolic variable on stack
        vars_stack = []
        for var_stack in config["stack"]:
            offset, size = var_stack[0], var_stack[1]
            var = claripy.BVS(str(offset), size) # take name as offset
            addr = state.regs.rbp-offset
            print(offset, addr, var, size)
            state.memory.store(addr, var) # setup symbolic variable
            vars_stack.append((addr, var)) # record var and address of var 
        

        # explore paths to reach target
        exploration = sm.explore(find=target)

        # Get our synchronized state back!
        founds = exploration.stashes["found"]
        if len(founds)==0:
            print("Target is not reachable!")
            exit(1)

        state = founds[0]
        
        # sync solved variable on stack back to running process
        for addr, var in vars_stack:
            val = state.solver.eval(var, cast_to=bytes) # solve AST to bytes
            addr = state.solver.eval(addr) # convert from BVV to Python int
            proj.concrete_target.write_memory(addr, val)

    

if __name__ == "__main__":
    args = parse_arg()
    symbolic(args)