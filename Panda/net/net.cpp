/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"

#define SIZE 10
#define MAX_LEN 14
// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
#include "osi/osi_types.h"
#include "osi/osi_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);
int on_replay_net_transfer(CPUState* env, uint32_t type, uint64_t src_adrr, 
    uint64_t dst_addr, uint32_t num_bytes);
int on_replay_handle_packet(CPUState *env, uint8_t *buf, int size, uint8_t
    direction, uint64_t old_buf_addr);

FILE *net_log;
}

char proc_to_track[MAX_LEN];
target_ulong process_asid = 0;

int on_replay_net_transfer(CPUState* env, uint32_t type, uint64_t src_addr, 
    uint64_t dst_addr, uint32_t num_bytes) {
    if (process_asid == 0) {
	OsiProc* proc = get_current_process(env);
	if (proc == NULL)
                return false;
        int len = (strlen(proc->name) < SIZE ? strlen(proc->name) : SIZE);	
	target_ulong current = panda_current_asid(env);
        if (strncmp(proc->name, proc_to_track, len) == 0 && current == proc->asid) {
		process_asid = proc->asid;
	}
    }
    target_ulong current = panda_current_asid(env);
    if (current == process_asid) {
        
    	fprintf(net_log, "net transfer: src: %lx, dst: %lx, n: %u\n", src_addr, dst_addr, num_bytes);
    
    }
    return 1;
}

int on_replay_handle_packet(CPUState *env, uint8_t *buf, int size, uint8_t
    direction, uint64_t old_buf_addr) {
    if (process_asid == 0) {
    OsiProc* proc = get_current_process(env);
    if (proc == NULL)
           return false;
    int len = (strlen(proc->name) < SIZE ? strlen(proc->name) : SIZE);	
    target_ulong current = panda_current_asid(env);
    if (strncmp(proc->name, proc_to_track, len) == 0 && current == proc->asid) {
	process_asid = proc->asid;
    	}
    }

    target_ulong current = panda_current_asid(env);
    if (current == process_asid) {
	    fprintf(net_log, "handle packets: buf: %p, size: %i, direction: %u, old_buf_addr: %lx\n",
		buf, size, direction, old_buf_addr);
		fprintf(net_log, "start content: \n");
		for (int i = 0; i < size; i++) {
		    fprintf(net_log, "%c, ", buf[i]);
		}
		fprintf(net_log, "\n end content \n");
    }
    return 1;
}

bool init_plugin(void *self) {
    panda_require("osi");
    assert(init_osi_api());

    panda_cb pcb;
    pcb.replay_net_transfer = on_replay_net_transfer;
    panda_register_callback(self, PANDA_CB_REPLAY_NET_TRANSFER, pcb);
    pcb.replay_handle_packet = on_replay_handle_packet;
    panda_register_callback(self, PANDA_CB_REPLAY_HANDLE_PACKET, pcb);

    panda_arg_list *args = panda_get_args("net");
    const char* process_name = panda_parse_string(args, "proc_name", NULL);
   
    if (process_name == NULL){
            printf("USAGE: you must indicate a specific 'proc_name'\n");
            return false;
    }
    if (strlen(process_name) > MAX_LEN)
            strncpy(proc_to_track, process_name, MAX_LEN);
    else
            strncpy(proc_to_track, process_name, strlen(process_name));
	
    net_log = fopen("network_detection.txt", "a");
    
    if (!net_log) {
	printf("File not found!\n");
	return false;
    }
    
    return true;
}

void uninit_plugin(void *self) {
    fclose(net_log);
}
