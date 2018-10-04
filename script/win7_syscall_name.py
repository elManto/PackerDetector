import win7_sp01_x86_syscalls
import sys

def main():
	
	log_to_parse = sys.argv[1]
	syscall_list = []
	proc_list = []
	f = open(log_to_parse, "r")
	for line in f:
		splitted_line = line.split("\t")
		proc_name = splitted_line[0]
		if proc_name not in proc_list:
			proc_list.append(proc_name)
		call_number = splitted_line[1][:-1]
		tmp_index = int(call_number, 16)
		if (tmp_index) > 4096:
			index = tmp_index-4096
			syscall_name = win7_sp01_x86_syscalls.syscalls[1][index]
			if syscall_name not in syscall_list:
				syscall_list.append(syscall_name)		
		else:
			index = tmp_index
			syscall_name = win7_sp01_x86_syscalls.syscalls[0][index]
			if syscall_name not in syscall_list:
				syscall_list.append(syscall_name)
	out = open("./behavioral_analysis.txt", "a")
	out.write("Processes:\t")
	for proc in proc_list:
		out.write(proc + "\t")
	out.write("\n")
	out.write("Syscalls:\n")
	for syscall in syscall_list:
		out.write(syscall + "\n")
		
		
	

if __name__ == "__main__":
	main()
