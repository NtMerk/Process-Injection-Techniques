## EarlyBird through Thread Hijacking Injection
This process injection technique inserts our payload into a newly spawned process and modifies the main thread's context to execute it. Specifically, the RIP register of the main thread is modified to our own payload. 
It does so in the following manner:
1. A new process is spawned using `CreateProcess` with the `CREATE_SUSPENDED` flag. 
2. HANDLEs to the process and its main threads are collected.
3. Memory is allocated in the process (`VirtualAllocEx`) and the payload is written to it (`WriteProcessMemory`).
4. The thread's context is retrieved (`GetThreadContext`), and the RIP is modified (`context.Rip = lpTargetAddress;`).
5. The thread's context is set with the new RIP value (`SetThreadContext`) and the thread is resumed (`ResumeThread`).
6. Finally, the payload is executed in by the thread at some point in time.

Note: the payload in the code will spawn a calculator and promptly kill the process it was injected in.

Note x2: it would be of interest to craft a payload that preserves the thread's context after executing.