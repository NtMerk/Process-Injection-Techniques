## PE Injection
This process injection technique inserts our payload into a desired process, and runs it spawning a new thread.
It does so in the following manner:
1. The desired process is found in the system using the APIs from the `tlhelp32.h` header.
2. Memory is allocated in the process (`VirtualAllocEx`) and the payload is written to it (`WriteProcessMemory`).
3. Finally, the payload is executed in the remote process spawning a new thread (`CreateRemoteThread`).

Note: the payload in the code will spawn a calculator and promptly kill the process it was injected in.