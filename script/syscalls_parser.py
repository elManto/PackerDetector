import sys

# USAGE: python syscalls_parser.py /path/to/behaviors.txt
# output: "./res.txt"

syscalls_list_path = "./syscalls.txt"

def main():
	log_to_parse = sys.argv[1]
	total_dict = dict()
	f = open(syscalls_list_path, "r")
	for line in f:
		tmp = line.split("\t")
		if len(tmp[1]) > 1:
			print tmp
			my_key = "0000" + tmp[1][2:-1]
			print my_key
			total_dict[my_key] = tmp[0]
			print "************************"
	print "Set up done..."
	#print total_dict
	parse_dict = dict()
	log = open(log_to_parse)
	for line in log:
		l = line.split("\t")
		if parse_dict.has_key(l[1][:-1]):
			parse_dict[l[1][:-1]] += 1
		else:
			parse_dict[l[1][:-1]] = 1
	print "Elaboration of results"
	out = open("./behavioral_analysis.txt", "a")
	for key in parse_dict:
		#print key
		if total_dict.has_key(key):
			# print key
			syscall_name = total_dict[key]
			freq = parse_dict[key]
			out.write(syscall_name + "\t" + str(freq) + "\n")
	print "Script ended correctly!"

if __name__ == "__main__":
	main()
