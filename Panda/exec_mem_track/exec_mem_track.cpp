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
#define ACCESS_MASK 805306368
#define OPEN_FILE 1
#define CREATE_FILE 0

extern "C"{
#include "osi/osi_types.h"
#include "osi/osi_ext.h"
#include "../syscalls2/gen_syscalls_ext_typedefs.h"
#include "../syscalls2/syscalls_common.h"
#include "../syscalls2/syscalls2_info.h"
#include "../syscalls2/syscalls2_int_fns.h"

bool init_plugin(void *);
void uninit_plugin(void *);

FILE *mem_log;
FILE *module_log;
FILE *behaviors_log;
FILE *page_log;
FILE *file_operation_log;
}


char proc_to_track[MAX_LEN];
OsiProc *proc = NULL;
OsiModules *ms = NULL;
target_ulong asid_to_track = 0;

std::map<target_ulong, target_ulong> my_modules;
std::list<target_ulong> page_list;
std::list<target_ulong> fake_pc;	// it stores pc values related to writes to module area operations
std::map <target_ulong, target_ulong> addr2pc;
std::map <target_ulong, target_ulong> packed_memory_area;
std::list<target_ulong> asid_list;


int virt_mem_after_write(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
bool translate_callback(CPUState *env, target_ulong pc);
void my_all_sys_enter_t(CPUState *env, target_ulong pc, target_ulong callno);
int before_block_callback(CPUState *env, TranslationBlock *tb);
// Hook function: NtCreateFile
void my_NtCreateFile_enter(CPUState* env, target_ulong pc, uint32_t FileHandle, uint32_t DesiredAccess, uint32_t ObjectAttributes, uint32_t IoStatusBlock, uint32_t AllocationSize, uint32_t FileAttributes, uint32_t ShareAccess, uint32_t CreateDisposition, uint32_t CreateOptions, uint32_t EaBuffer, uint32_t EaLength);
// Hook function: NtOpenFile
void my_NtOpenFile_enter(CPUState* env, target_ulong pc, uint32_t FileHandle, uint32_t DesiredAccess, uint32_t ObjectAttributes, uint32_t IoStatusBlock, uint32_t ShareAccess, uint32_t OpenOptions);

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
 
	pcb.before_block_exec = before_block_callback;
	panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

	#ifdef TARGET_I386
        PPP_REG_CB("syscalls2", on_all_sys_enter, my_all_sys_enter_t);
	PPP_REG_CB("syscalls2", on_NtCreateFile_enter, my_NtCreateFile_enter);
	PPP_REG_CB("syscalls2", on_NtOpenFile_enter, my_NtOpenFile_enter);
	#endif
   
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
	page_log = fopen("pages.txt", "a");
	file_operation_log = fopen("file_operations.txt", "a");	

	if (!mem_log || !module_log || !behaviors_log || !page_log || !file_operation_log) {
		printf("File not found\n");
		return false;
	}

	return true;
}


void my_all_sys_enter_t(CPUState *env, target_ulong pc, target_ulong callno)
{
        /*proc = get_current_process(env);
        if (proc == NULL)
                return;*/
	target_ulong current = panda_current_asid(env);
	bool found = (std::find(asid_list.begin(), asid_list.end(), current) != asid_list.end());

        //bool found = (strcmp(proc->name, proc_to_track) == 0);
        if(found) 
                fprintf(behaviors_log, "" TARGET_FMT_lx "\n", callno);
}

void my_check_access(target_ulong current, uint32_t DesiredAccess, int func)
{
	bool found = (std::find(asid_list.begin(), asid_list.end(), current) != asid_list.end());
        if(found) {
		uint32_t masked = DesiredAccess & ACCESS_MASK;
		if (masked != 0) {
			if (func == CREATE_FILE) {
				fprintf(file_operation_log, "NtCreateFile with eXecute access was detected->DesiredAccess: %u\n", DesiredAccess);
			}
			if (func == OPEN_FILE) {
				fprintf(file_operation_log, "NtoPENFile with eXecute access was detected->DesiredAccess: %u\n", DesiredAccess);
			}
		}
	}
}

void my_NtOpenFile_enter(CPUState* env, target_ulong pc, uint32_t FileHandle, uint32_t DesiredAccess, uint32_t ObjectAttributes, uint32_t IoStatusBlock, uint32_t ShareAccess, uint32_t OpenOptions)
{
	target_ulong current = panda_current_asid(env);
	my_check_access(current, DesiredAccess, OPEN_FILE);
}


void my_NtCreateFile_enter(CPUState* env, target_ulong pc, uint32_t FileHandle, uint32_t DesiredAccess, uint32_t ObjectAttributes, uint32_t IoStatusBlock, uint32_t AllocationSize, uint32_t FileAttributes, uint32_t ShareAccess, uint32_t CreateDisposition, uint32_t CreateOptions, uint32_t EaBuffer, uint32_t EaLength)
{
	target_ulong current = panda_current_asid(env);
	my_check_access(current, DesiredAccess, CREATE_FILE);
}


int virt_mem_after_write(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf)
{
	target_ulong current = panda_current_asid(env);
	if (current == -1)
		return 0;
	bool found = (std::find(asid_list.begin(), asid_list.end(), current) != asid_list.end());
	if(found) {
		
		std::map<target_ulong, target_ulong>::iterator it = addr2pc.find(addr);
		if(it == addr2pc.end())
			addr2pc[addr] = env->panda_guest_pc; // stores a written virtual address and current program counter's value 
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
	if (strncmp(proc->name, proc_to_track, len) == 0) 
	{
		target_ulong asid = panda_current_asid(env);	
		if (asid != proc->asid) {
			free_osiproc(proc);
			return false;
		}
		ms = get_libraries(env, proc);
		if (ms != NULL) {
			for (int i = 1; i < ms->num; i++) {
				std::map<target_ulong, target_ulong>::iterator ms_it = my_modules.find(ms->module[i].base);
				if(ms_it == my_modules.end()) {
					my_modules[ms->module[i].base] = ms->module[i].size;
				}		
			}
		}
		bool found = (std::find(asid_list.begin(), asid_list.end(), asid) != asid_list.end());
		if (!found)
			asid_list.push_back(asid);	
		std::map<target_ulong, target_ulong>::iterator it = addr2pc.find(env->panda_guest_pc);
		if (it != addr2pc.end())
		{
			if (ms == NULL) {
        			fprintf(module_log, "No mapped dynamic libraries.\n");
    			} else {
        			for (int i = 1; i < ms->num; i++) {	// we start at '1' because module '0' is the one corresponding to the executable file
					if (it->first >= ms->module[i].base && it->first <= (ms->module[i].base + ms->module[i].size)) {
						fprintf(module_log, "writing on module area: %s, " TARGET_FMT_lx "\n", ms->module[i].name, ms->module[i].base);
						fprintf(module_log, TARGET_FMT_lx "\t\t" TARGET_FMT_lx "\n\n", it->first, it->second);
						is_module_write = true;
						bool pc_contained = (std::find(fake_pc.begin(), fake_pc.end(), it->second) != fake_pc.end());
						if (!pc_contained)
							fake_pc.push_back(it->second);
					}
            			}
    				free_osimodules(ms);
			}
			//bool last_check = is_write_to_module_pc(it->second);
			if (!is_module_write /*&& !last_check*/)
				packed_memory_area[it->first] = it->second;  
				//fprintf(mem_log, TARGET_FMT_lx "\t\t" TARGET_FMT_lx "\n\n", it->first, it->second);

		}
		
	}
	free_osiproc(proc);
		
	return false;
	
}


bool is_page_containing_module(target_ulong page_addr) 
{
	for(std::map<target_ulong, target_ulong>::iterator it = my_modules.begin(); it != my_modules.end(); it++) {
		if(page_addr >= it->first && page_addr <= it->first + it->second) 
			return true;
	}	
	return false;
}


int before_block_callback(CPUState *env, TranslationBlock *tb) 
{
	/*if(asid_to_track == 0) {
		proc = get_current_process(env);
		if (proc == NULL)
			return false;
		int len = (strlen(proc->name) < SIZE ? strlen(proc->name) : SIZE);
		if (strncmp(proc->name, proc_to_track, len) == 0 && !panda_in_kernel(env)) {	
			asid_to_track = proc->asid;
			target_ulong page1 = tb->pc & TARGET_PAGE_MASK;
			target_ulong page2 = (tb->pc + tb->size) & TARGET_PAGE_MASK;	
			bool found1 = (std::find(page_list.begin(), page_list.end(), page1) != page_list.end());
			
			if (!found1) 
				page_list.push_back(page1);
			bool found2 = (std::find(page_list.begin(), page_list.end(), page2) != page_list.end());	
			if (!found2) 
				page_list.push_back(page2);
		}
		free_osiproc(proc);

	}*/
	target_ulong current = panda_current_asid(env);
	bool found = (std::find(asid_list.begin(), asid_list.end(), current) != asid_list.end());
	if (found && !panda_in_kernel(env)) {
		target_ulong page1 = tb->pc & TARGET_PAGE_MASK;
		target_ulong page2 = (tb->pc + tb->size) & TARGET_PAGE_MASK;	
		bool found1 = (std::find(page_list.begin(), page_list.end(), page1) != page_list.end());
		if (!found1) 
			page_list.push_back(page1);
		bool found2 = (std::find(page_list.begin(), page_list.end(), page2) != page_list.end());

		if (!found2) 
			page_list.push_back(page2);

	}
	
	
	return 0;	
}

void uninit_plugin(void * self)
{
	FILE* asid_log = fopen("asid.txt", "a");
	if(asid_log)
		for(std::list<target_ulong>::iterator it = asid_list.begin(); it != asid_list.end(); it++)
			fprintf(asid_log, "" TARGET_FMT_lx "\n", *it);
	
	for(std::map<target_ulong, target_ulong>::iterator it = packed_memory_area.begin(); it != packed_memory_area.end(); it++) {
		//if(!is_write_to_module_pc(it->second))
			fprintf(mem_log, TARGET_FMT_lx "\t\t" TARGET_FMT_lx "\n", it->first, it->second);
	}
	for(std::list<target_ulong>::iterator it = page_list.begin(); it != page_list.end(); it++) {
		if(!is_page_containing_module(*it))
			fprintf(page_log, "page: " TARGET_FMT_lx "\n", *it);
	}
	fclose(mem_log);
	fclose(module_log);
	fclose(behaviors_log);
	fclose(page_log);
	fclose(file_operation_log);

	panda_disable_memcb();
	panda_disable_precise_pc();
}
