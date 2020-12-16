import os 
import time
start = time.time()
path = "/home/osboxes/malware_data_science/ch8/data/benignware/"
files = os.listdir(path)
import pefile
from capstone import *
success = 0
fail = 0
success_path = "/home/osboxes/Desktop/success_disassembly.txt"
success_txt = open(success_path,"a")
fail_path = "/home/osboxes/Desktop/fail_disassembly.txt"
fail_txt = open(fail_path,"a")
for i in files :
	try:
		pe = pefile.PE(path+i)
		entrypoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
		entrypoint_address = entrypoint+pe.OPTIONAL_HEADER.ImageBase
		binary_code = pe.get_memory_mapped_image()[entrypoint:entrypoint+100]
		disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
		success_txt.write(i)
		success_txt.write('\n')
		for instruction in disassembler.disasm(binary_code, entrypoint_address):
    			success_txt.write("%s\t%s" %(instruction.mnemonic, instruction.op_str))
			success_txt.write('\n')
			#print "%s\t%s" %(instruction.mnemonic, instruction.op_str)
		success_txt.write('\n')
		success_txt.write('-----------------------------------------------------------------------------')
		success_txt.write('\n')
		success += 1
	except :
		fail_txt.write(i)
		fail_txt.write('\n')
		fail += 1
success_txt.close()
fail_txt.close()
print "success:",success
print "fail:",fail
end = time.time()
print end-start
		
