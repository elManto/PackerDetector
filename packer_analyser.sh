# !/bin/bash

sample=$1
record=$sample
mkdir $sample
echo "Analysing sample "$sample
$PANDA/i386-softmmu/qemu-system-i386 -m 2048 -hda win7x86.img -replay $record -panda osi -os windows-32-7 -panda syscalls2:profile=windows_7_x86 -panda exec_mem_track:proc_name=$sample
echo "First plugin ended its execution!"
if [ -s memory_detection.txt ]
then
	echo "File 'memory_detection' NOT empty"
	echo "packed" > result.txt
else
	echo "File 'memory_detection' empty"
	python win7_syscall_name.py /home/elmanto/behaviors.txt
	mv behavioral_analysis.txt $sample/
	echo "not packed/virtual env detection" > result.txt
fi
mv module_detection.txt $sample/
mv memory_detection.txt $sample/
mv behaviors.txt $sample/
mv asid.txt $sample/
mv result.txt $sample/
rm $record-rr-*
mv $sample/ Analysed/
mv LowEntropySamples1/$sample Analysed_sample/

