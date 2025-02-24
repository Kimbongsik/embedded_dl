import lief
import sys
import cfgReader

DEBUG = 1 # if debug 1 -> print

STT_FUNC = 2 #LIEF::ELF::Symbol::TYPE : FUNC(executable code)
STT_GV = 1 #LIEF::ELF::Symbol::TYPE : OBJECT(data object)

class ElfParser:
    def __init__(self, elf_file, cfg_file):
        self.elf_file = lief.parse(elf_file)
        self.cfg = cfgReader.CfgData(cfg_file)
        self.cfg.read_cfg()
        self.Func = []
        self.GV = []

    # check ARM/Thumb mode
    def check_mode(self, input_addr):
        if input_addr %2 == 1:
            MODE = 2
        else:
            MODE = 4

        return MODE

    def set_sym_addr_table(self):

        for symbol in self.elf_file.symbols:
            tmp = []
            if symbol.name in self.cfg.called_functions and symbol.type == STT_FUNC:
                MODE = self.check_mode(symbol.value)

                if DEBUG == True:
                    print(f"function name: {symbol.name}, addr: {hex((symbol.value) - (MODE == 2))}")
                tmp.append(symbol.name)
                tmp.append(symbol.value - (MODE == 2))
                self.Func.append(tmp)
            
            if symbol.name in self.cfg.global_vars and symbol.type == STT_GV:
                if DEBUG == True:
                    print(f"global variable name: {symbol.name}, addr: {hex(symbol.value)}")
                tmp.append(symbol.name)
                tmp.append(symbol.value)
                self.GV.append(tmp)

    def sym_addr_table_to_bin_file(self, entity_filename):
        with open(entity_filename, "wb") as f:
            offset = 0
            for i in range(len(self.Func)):
                func_name = self.Func[i][0].encode('utf-8')
                func_addr = self.Func[i][1].to_bytes(4, 'little')
                f.write(bytes(offset.to_bytes(4, 'little')))
                f.write(len(func_name).to_bytes(4, 'little'))
                f.write(bytes(func_name)) # func_name
                f.write(bytes(func_addr)) # func_addr
                
                offset += 4 + 4 + len(func_name) + 4

            for i in range(len(self.GV)):
                gv_name = self.GV[i][0].encode('utf-8')
                gv_addr = self.GV[i][1].to_bytes(4, 'little')
                f.write(bytes(offset.to_bytes(4, 'little')))
                f.write(len(gv_name).to_bytes(4, 'little'))
                f.write(bytes(gv_name)) # gv_name
                f.write(bytes(gv_addr)) # gv_addr

                offset += 4 + 4 + len(gv_name) + 4

    def get_address_from_bin_file(self, entity_filename, target_name):
        with open(entity_filename, "rb") as f:
            while True:
                offset = int.from_bytes(f.read(4), 'little') 
                name_length = int.from_bytes(f.read(4), 'little') 
                name = f.read(name_length).decode('utf-8') 
                addr = int.from_bytes(f.read(4), 'little') 

                if name == target_name:
                    return addr

    def make_func_bin_file(self, func_dir, func_name):
        target_sym = None
        
        for symbol in self.elf_file.symbols:
            if symbol.name == func_name and symbol.type == STT_FUNC:
                target_sym = symbol
        
        func_start_addr = target_sym.value - (self.check_mode(target_sym.value) == 2)
        func_size = target_sym.size

        text_section = self.elf_file.get_section(".text")
        text_start = text_section.virtual_address - (self.check_mode(text_section.virtual_address) == 2)
        text_offset = text_section.offset
        text_data = text_section.content

        if not (text_start <= func_start_addr < text_start + len(text_data)):
            print(f"Err) Function '{func_name}' is out of .text section. ")
            return None

        func_offset = func_start_addr - text_start + text_offset
        func_bin = text_data[func_offset - text_offset : func_offset - text_offset + func_size] # output binary

        bin_file_path = func_dir + func_name + ".bin"
        print("bin_file_name: ", bin_file_path)

        with open(bin_file_path, "wb") as f:
            f.write(func_bin)
    
        print(f"Succeed to save '{func_name}.bin at '{bin_file_path}'")

        return bytes(func_bin)


# test
# file_name = "../example_task2/Debug/example.elf"
# cfg_file_name = "../CFGbin/example_task2_CFGInfo.bin"
# entity_filename = "../AddrTable/example_task2/EntityTable.bin"
# func_dir = "../Funcbin/example_task2/"
# test = ElfParser(file_name, cfg_file_name)
# test.set_sym_addr_table()
# test.sym_addr_table_to_bin_file(entity_filename)
# print("test_f address: ", hex(test.get_address_from_bin_file(entity_filename, "test_f")))
# print("test_f binary: ", test.make_func_bin_file(func_dir, "test_f"))