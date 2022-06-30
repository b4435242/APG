import llvmlite.binding as llvm
from ctypes import CFUNCTYPE, c_int
import ctypes


class transformer:
    def __init__(self):
        llvm.initialize()
        llvm.initialize_native_target()
        llvm.initialize_native_asmprinter()
        self.engine = self.create_execution_engine()

    def create_execution_engine(self):
        '''
        Create an ExecutionEngine suitable for JIT code generation on
        the host CPU.  The engine is reusable for an arbitrary number of
        modules.
        '''
        # Create a target machine representing the host
        target = llvm.Target.from_default_triple()

        print(target)
        target_machine = target.create_target_machine()
        # And an execution engine with an empty backing module
        backing_mod = llvm.parse_assembly("")
        engine = llvm.create_mcjit_compiler(backing_mod, target_machine)
        return engine


    def compile_ir(self, llvm_ir):
        '''
        Compile the LLVM IR string with the given engine.
        The compiled module object is returned.
        '''
        # Create a LLVM module object from the IR
        module = llvm.parse_assembly(llvm_ir)
        module.verify()
        module.triple = llvm.get_default_triple()
        # Now add the module and make sure it is ready for execution
        self.engine.add_module(module)
        self.engine.finalize_object()
        self.engine.run_static_constructors()


       
        return str(module)

    def run_toy_server_testcase(self):
        func_ptr = self.engine.get_function_address("constraints")

        # Run the function via ctypes
        cfunc = CFUNCTYPE(ctypes.c_bool, c_int)(func_ptr)
        res_0 = cfunc(1)
        res_1 = cfunc(-1)
        print("constraints(1) = %d, constraints(-1) = %d"%(res_0, res_1))

    def run_cve21773_testcase(self):
        func_ptr = self.engine.get_function_address("constraints")

        # Run the function via ctypes
        cfunc = CFUNCTYPE(ctypes.c_bool, ctypes.c_wchar_p)(func_ptr)
        s = "/.."
        res = cfunc(ctypes.c_wchar_p(s))
        print("constraints(%s) = %d "% (s ,res))

