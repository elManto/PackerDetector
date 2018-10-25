import win7_sp01_x86_syscalls
import sys
# Interesting behaviors: registry activity, mutex activity
 
def main():

	log_to_parse = sys.argv[1]
	syscall_list = []
	proc_list = []
	flagged_behaviors = []
	f = open(log_to_parse, "r")
	for line in f:
		call_number = line[:-1]
		tmp_index = int(call_number, 16)
		if tmp_index > 4096:
			index = tmp_index-4096
			syscall_name = win7_sp01_x86_syscalls.syscalls[1][index]
			if syscall_name not in syscall_list:
				syscall_list.append(syscall_name)
			if syscall_name in win7_sp01_x86_syscalls.flagged_behaviors and syscall_name not in flagged_behaviors:
				flagged_behaviors.append(syscall_name)		
		else:
			index = tmp_index
			syscall_name = win7_sp01_x86_syscalls.syscalls[0][index]
			if syscall_name not in syscall_list:
				syscall_list.append(syscall_name)
			if syscall_name in win7_sp01_x86_syscalls.flagged_behaviors and syscall_name not in flagged_behaviors:
				flagged_behaviors.append(syscall_name)		

	out = open("./behavioral_analysis.txt", "a")
	out.write("Syscalls:\n")
	for syscall in syscall_list:
		out.write(syscall + "\n")

	suspicious_behaviors = open("./flagged_behaviors.txt", "a")
	for syscall in flagged_behaviors:
		suspicious_behaviors.write(syscall + "\n")	
		
	

if __name__ == "__main__":
	main()
