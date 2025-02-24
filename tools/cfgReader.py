import struct
import lief

DEBUG = 0 # if debug 1 -> print

class CfgData:
    def __init__(self, cfg_file):
        self.cfg_file = cfg_file
        if not self.cfg_file:
            raise ValueError("Could not load ELF.")
        self.called_functions = []
        self.global_vars = []

    def read_cfg(self):
        with open(self.cfg_file, "rb") as f:
            while True:
                # FunctionInfo 구조체
                function_info_data = f.read(12)
                if not function_info_data:
                    print("Finished to read CFG file.")
                    break
                
                function_len, call_count, global_var_count = struct.unpack("III", function_info_data)

                #Function name
                function_name = f.read(function_len).decode("utf-8")
                if DEBUG == True:
                    print(f"Function: {function_name}")
                    print(f"  Calls {call_count} functions")
                    print(f"  Uses {global_var_count} global variables")

                #Called functions
                for _ in range(call_count):
                    func_size = struct.unpack("I", f.read(4))[0]
                    func_name = f.read(func_size).decode("utf-8")
                    if DEBUG == True:
                        print(f"     Called function: ", func_name)
                    self.called_functions.append(func_name)

                #Called Global variables
                for _ in range(global_var_count):
                    gv_size = struct.unpack("I", f.read(4))[0]
                    gv_name = f.read(gv_size).decode("utf-8")
                    if DEBUG == True:
                        print(f"     Used global variable: ", gv_name)
                    self.global_vars.append(gv_name)

    def print_for_debug(self):
        for func in self.called_functions:
            print(f" Debug: Calls: {func}")
        for gv in self.global_vars:
            print(f" Debug: Global Var: {gv}")



        
    

