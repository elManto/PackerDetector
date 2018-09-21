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
#define RANGE 100

extern "C"{
#include "osi/osi_types.h"
#include "osi/osi_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);

FILE * mem_log;
//FILE * instr_log;
FILE * module_log;
FILE * behaviors_log;
}


char proc_to_track[MAX_LEN];
OsiProc *proc = NULL;
OsiModules *ms = NULL;

std::list<target_ulong> fake_pc;	// it stores pc values related to writes to module area operations
std::map <target_ulong, target_ulong> addr2pc;
std::map <target_ulong, target_ulong> packed_memory_area;
std::list<target_ulong> asid_list;

int virt_mem_after_write(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
bool translate_callback(CPUState *env, target_ulong pc);

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


	mem_log = fopen("memory_detection.txt", "a");
	module_log = fopen("module_detection.txt", "a");
	behaviors_log = fopen("behaviors.txt", "a");

	if (!mem_log || !module_log || !behaviors_log) {
		printf("File not found\n");
		return false;
	}

	//instr_log = fopen("instr_count.txt", "a");
	//fprintf(mem_log, "Accessed address\t\tProgram counter\n");
	return true;
}


int virt_mem_after_write(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf)
{
	// TODO: implement using asid instead of get_current_process()	
	//proc = get_current_process(env);
	//bool found = (strcmp(proc->name, proc_to_track) == 0);
	//target_ulong current;
	target_ulong current = panda_current_asid(env);
	if (current == -1)
		return 0;
	bool found = (std::find(asid_list.begin(), asid_list.end(), current) != asid_list.end());
	//bool found = (current == 131203072);
	if(found) {
		
		std::map<target_ulong, target_ulong>::iterator it = addr2pc.find(addr);
		proc = get_current_process(env);
		if (proc == NULL)
			return 0;
		
		if(it == addr2pc.end() && (strcmp(proc_to_track, proc->name) == 0))
			addr2pc[addr] = env->panda_guest_pc; // stores a written virtual address and current program counter's value 
			
		free_osiproc(proc);
	}

	return 0;
}


/*
This method returns true when the pc passed as input is close to the pc values corresponding to the writes to a module area. 
*/
bool is_write_to_module_pc(target_ulong my_pc) {
	for(std::list<target_ulong>::iterator it = fake_pc.begin(); it != fake_pc.end(); it++) {
		if(my_pc <= *(it) + RANGE || my_pc >= *(it) - RANGE)
			return true;
	}	
	return false;
}


bool translate_callback(CPUState *env, target_ulong pc)
{	
	bool is_module_write = false;
	// Checks if pc matches with a virt mem address which has been written before
	proc = get_current_process(env);
	if (proc == NULL)
		return false;
	int len = (strlen(proc->name) < SIZE ? strlen(proc->name) : SIZE);
	if (strncmp(proc->name, proc_to_track, len) == 0) //better remove???
	{
		target_ulong asid = panda_current_asid(env);	
		bool found = (std::find(asid_list.begin(), asid_list.end(), asid) != asid_list.end());

		if (!found)
			asid_list.push_back(asid);	
		std::map<target_ulong, target_ulong>::iterator it = addr2pc.find(env->panda_guest_pc);//env->panda_guest_pc
		if (it != addr2pc.end())
		{
			ms = get_libraries(env, proc);
			if (ms == NULL) {
        			fprintf(module_log, "No mapped dynamic libraries.\n");
    			} else {
        			//fprintf(mem_log, "Dynamic libraries list (%d libs):\n", ms->num);
        			for (int i = 0; i < ms->num; i++) {
					if (it->first >= ms->module[i].base && it->first <= (ms->module[i].base + ms->module[i].size)) {
						fprintf(module_log, "writing on module area: %s\n", ms->module[i].name);
						fprintf(module_log, TARGET_FMT_lx "\t\t" TARGET_FMT_lx "\n\n", it->first, it->second);
						is_module_write = true;
						bool pc_contained = (std::find(fake_pc.begin(), fake_pc.end(), it->second) != fake_pc.end());
						if (!pc_contained)
							fake_pc.push_back(it->second);
					}
            			//fprintf(mem_log, "\t0x" TARGET_FMT_lx "\t" TARGET_FMT_ld "\t%-24s %s\n", ms->module[i].base, ms->module[i].size, ms->module[i].name, ms->module[i].file);
				}
    				free_osimodules(ms);
			}
			bool last_check = is_write_to_module_pc(it->second);
			if (!is_module_write && !last_check)
				packed_memory_area[it->first] = it->second;  
				//fprintf(mem_log, TARGET_FMT_lx "\t\t" TARGET_FMT_lx "\n\n", it->first, it->second);

		}
		unsigned char buf[2];
		cpu_memory_rw_debug(env, pc, buf, 2, 0);
                if (buf[0] == 0x0F && buf[1] == 0x34) {
			#ifdef TARGET_I386
			CPUX86State *cpu = (CPUX86State *) env->env_ptr;
			// On Windows and Linux, the system call id is in EAX
			fprintf(behaviors_log, "SYSCALL\t" TARGET_FMT_lx "\n",cpu->regs[R_EAX]);
			#endif
		}

		/*if (first_instr == 0)
			first_instr = rr_get_guest_instr_count();
		else
			last_instr = rr_get_guest_instr_count();*/

	}
	free_osiproc(proc);
		
	return false;
	
}



void uninit_plugin(void * self)
{
	//fclose(pc_log);
	FILE* asid_log = fopen("asid.txt", "a");
	if(asid_log)
		for(std::list<target_ulong>::iterator it = asid_list.begin(); it != asid_list.end(); it++)
			fprintf(asid_log, "" TARGET_FMT_lx "\n", *it);
	
	for(std::map<target_ulong, target_ulong>::iterator it = packed_memory_area.begin(); it != packed_memory_area.end(); it++) {
		if(!is_write_to_module_pc(it->second))
			fprintf(mem_log, TARGET_FMT_lx "\t\t" TARGET_FMT_lx "\n", it->first, it->second);
	}
	fclose(mem_log);
	fclose(module_log);
	fclose(behaviors_log);
	/*if (instr_log) {
		if (first_instr != last_instr) 
			fprintf(instr_log, "" TARGET_FMT_lx "\n", last_instr);
	}
	fclose(instr_log);*/

	panda_disable_memcb();
	panda_disable_precise_pc();
}
