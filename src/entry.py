import subprocess
import avatar2 
import time

import angr
import claripy
from angr_targets import AvatarGDBConcreteTarget

# local module
import variable
import params
import llvmir_lifter
import llvm_transformer

GDB_SERVER_IP = '127.0.0.1'



def symbolic(binary, ctrl, data, GDB_SERVER_PORT, dynamic_base):
    
    # Instantiation of the AvatarGDBConcreteTarget
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64,
                                        GDB_SERVER_IP, GDB_SERVER_PORT)
    
    # Creation of the project with the new attributes 'concrete_target' 
    proj = angr.Project(binary, concrete_target=avatar_gdb, main_opts={'base_addr': dynamic_base})
    breakpoint = ctrl["breakpoint"][0]
    target = ctrl["target"][0]

 
    print("setup break point %x" % breakpoint)
    proj.concrete_target.set_breakpoint(breakpoint)

    while True:

        proj.concrete_target.run() # continue until breakpoint
        state = proj.factory.entry_state(addr=breakpoint) # start symbolic execution from breakpoint
        state.concrete.sync() # sync state from running process through gdbserver

        state.options.add(angr.options.SYMBION_SYNC_CLE)
        state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)

        print("breakpoint triggered! pc=%x"%(state.solver.eval(state.regs.pc)))
        
        var_management = variable.SymVar(data, state)
        state = var_management.state
        sm = proj.factory.simulation_manager(state)

        # explore paths to reach target
        exploration = sm.explore(find=target)

        # Get our synchronized state back!
        founds = exploration.stashes["found"]
        if len(founds)==0:
            print("Target is not reachable!")
            exit(1)

        state = founds[0]
        print("good")
        var_management.sync_to_monitored(state, proj)
        expr = var_management.aggregate_constraints(state)
        return expr

def main():
    binary, ctrl, data, GDB_SERVER_PORT, dynamic_base = params.parse_params()
    expr = symbolic(binary, ctrl, data, GDB_SERVER_PORT, dynamic_base)
    lifter = llvmir_lifter.lifter()
    llvm_ir = lifter.lift(expr=expr)
    transformer = llvm_transformer.transformer()
    module = transformer.compile_ir(llvm_ir)
    
    with open('tmp.ll', 'w') as f:
        f.write(module)

    transformer.run_cve21773_testcase()
    #transformer.run_toy_server_testcase()


if __name__ == "__main__":
    main()
    