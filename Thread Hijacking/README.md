## Thread Hijacking Injection
This process injection technique inserts our payload into a desired process and modifies the main thread's context to execute it. Specifically, the RIP register of the main thread is modified to our own payload. 
It does so in the following manner:
1. The desired process is found in the system using the APIs from the `tlhelp32.h` header.
2. Memory is allocated in the process (`VirtualAllocEx`) and the payload is written to it (`WriteProcessMemory`).
3. The main thread is found in the system using the APIs from the `tlhelp32.h` header.
4. A handle to the thread is retrieved and the thread is suspended (`SuspendThread`).
5. The thread's context is retrieved (`GetThreadContext`), and the RIP is modified (`context.Rip = lpTargetAddress;`).
6. The thread's context is set with the new RIP value (`SetThreadContext`) and the thread is resumed (`ResumeThread`).
7. Finally, the payload is executed in by the thread at some point in time.

Note: the payload in the code will spawn a calculator and promptly kill the process it was injected in.