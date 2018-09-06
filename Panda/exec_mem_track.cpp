/*

  This plugin detects if a specific process perform an access to 
  memory in order to write something that then is executed. It is based
  on 'osi' plugin because it needs to understand when the indicated 
  process is active.
  USAGE:
	$PANDA/i386-softmmu/qemu-system-i386 -m 2048 -hda win7x86.img -replay panda_record/pa_fish_upx \
	-panda osi -os windows-32-7 -panda exec_mem_track:proc_name=pafish_upx_packed.exe

 */
#include "panda/plugin.h"
#include "panda/plugin_plugin.h"
#include "cpu.h"
#include "qemu-common.h"
#include <map>
#include <list>
#include <stdio.h>
#include <algorithm>

#define MAX_LEN 14
#define SIZE 10

extern "C"{
#include "osi/osi_types.h"
#include "osi/osi_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);

FILE * mem_log;
FILE * instr_log;
FILE * behaviors_log;
}

target_ulong first_instr, last_instr, total;

char proc_to_track[MAX_LEN];
OsiProc *proc = NULL;
std::map <target_ulong, target_ulong> addr2pc;
std::list<target_ulong> asid_list;

int virt_mem_after_write(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
bool translate_callback(CPUState *env, target_ulong pc);
int exec_callback(CPUState *env, target_ulong pc);

bool init_plugin(void* self)
{
	panda_require("osi");
	panda_enable_memcb(); // enables memory callbacks
	panda_cb pcb;
	panda_enable_precise_pc();
	
	assert(init_osi_api());

	pcb.virt_mem_after_write = virt_mem_after_write;
	panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_WRITE, pcb);

    	pcb.insn_translate = translate_callback;
    	panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);
    
	pcb.insn_exec = exec_callback;
	panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);

	panda_arg_list *args = panda_get_args("exec_mem_track");
	const char* process_name = panda_parse_string(args, "proc_name", NULL);
	if (process_name == NULL){
		printf("USAGE: you must indicate a specific 'proc_name'\n");
		return false;	
	}
	if (strlen(process_name) > MAX_LEN)
		strncpy(proc_to_track, process_name, MAX_LEN);
	else
		strncpy(proc_to_track, process_name, strlen(process_name));

	first_instr = 0;
	last_instr = 0;
	
	mem_log = fopen("memory_detection.txt", "a");
	if (!mem_log){
		printf("File not found\n");
		return false;
	}
	
	instr_log = fopen("instr_count.txt", "a");
	behaviors_log = fopen("behaviors.txt", "a");
	fprintf(mem_log, "Accessed address\t\tProgram counter\n");
	return true;
}

int virt_mem_after_write(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf)
{
	//proc = get_current_process(env);
	//bool found = (strcmp(proc->name, proc_to_track) == 0);
	//target_ulong current;
	target_ulong current = panda_current_asid(env);
	if(current == 0)
		return -1;
	bool found = (std::find(asid_list.begin(), asid_list.end(), current) != asid_list.end());
	if(found) {
		std::map<target_ulong, target_ulong>::iterator it = addr2pc.find(addr);
		if(it == addr2pc.end())
			addr2pc[addr] = env->panda_guest_pc;	// stores a written virtual address and current program counter's value 
		
	}
	//free_osiproc(proc);
	return 0;
}


bool translate_callback(CPUState *env, target_ulong pc)
{	
	// Checks if pc matches with a virt mem address which has been written before
	unsigned char buf[2];
	total = rr_get_guest_instr_count();

	proc = get_current_process(env);
	if (proc == NULL)
		return false;
	int len = (strlen(proc->name) < SIZE ? strlen(proc->name) : SIZE);
	if (strncmp(proc->name, proc_to_track, len) == 0) //better remove???
	{
		/*if (instr_log) {
			target_ulong tmp;
			tmp = rr_get_guest_instr_count();
			fprintf(instr_log, "" TARGET_FMT_lx "\n", tmp);
		}*/
		if(first_instr == 0)
			first_instr = rr_get_guest_instr_count();
		else
			last_instr = rr_get_guest_instr_count();
		
		target_ulong asid = panda_current_asid(env);	
		bool found = (std::find(asid_list.begin(), asid_list.end(), asid) != asid_list.end());
		if (!found)
			asid_list.push_back(asid);	
		std::map<target_ulong, target_ulong>::iterator it = addr2pc.find(env->panda_guest_pc);
		if (it != addr2pc.end())
		{
			fprintf(mem_log, TARGET_FMT_lx "\t\t" TARGET_FMT_lx "\n", it->first, it->second);

		}
		// Here we get the behaviors!
		cpu_memory_rw_debug(env, pc, buf, 2, 0);
    		if (buf[0] == 0x0F && buf[1] == 0x34)
			free_osiproc(proc);
        		return true;
		
	}
	free_osiproc(proc);
	return false;
	
}


int exec_callback(CPUState *env, target_ulong pc) {
#ifdef TARGET_I386
	CPUX86State *cpu = (CPUX86State *) env->env_ptr;
    	// On Windows and Linux, the system call id is in EAX
    	fprintf(behaviors_log,
    	"SYSCALL\t" TARGET_FMT_lx "\n",
    	cpu->regs[R_EAX]);
#endif
    return 0;
}


void uninit_plugin(void * self)
{
	//fclose(pc_log);
	FILE* asid_log = fopen("asid.txt", "a");
	if(asid_log)
		for(std::list<target_ulong>::iterator it = asid_list.begin(); it != asid_list.end(); it++)
			fprintf(asid_log, "" TARGET_FMT_lx "\n", *it);
	fclose(mem_log);
	//target_ulong total = rr_get_guest_instr_count();
	if (instr_log) {
		fprintf(instr_log, "" TARGET_FMT_lx "\n", first_instr);
		fprintf(instr_log, "" TARGET_FMT_lx "\n", last_instr);
		fprintf(instr_log, "" TARGET_FMT_lx "\n", total);

	}
	fclose(instr_log);
	panda_disable_memcb();
	panda_disable_precise_pc();
}

