# Plugin: exec_mem_track

## Summary
This plugin detects if a specific process performs an access to memory in order to write something that then is executed. 
It is useful when we want to detect the first layer of a packer. The output is a file of the accesses to memory in write mode
(only the addresses that then are executed!) and a file containing the asid of the processes we want to track.

## Arguments
1. The name of the process we want to track

## Dependencies
The "exec_mem_track" plugin depends on the "osi" plugin. It is written to work with windows executables mainly.

## Example

```
$PANDA/i386-softmmu/qemu-system-i386 -m 2048 -hda win7x86.img -replay panda_record/pa_fish_upx -panda osi \
-os windows-32-7 -panda exec_mem_track:proc_name=pafish_upx_packed.exe

```
