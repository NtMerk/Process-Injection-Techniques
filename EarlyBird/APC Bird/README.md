## EarlyBird through APC Injection
This process injection technique inserts our payload into a newly spawned process and queues an APC pointing to our payload to execute it.

It does so in the following manner:
1. A new process is spawned using `CreateProcess` with the `CREATE_SUSPENDED` flag. 
2. HANDLEs to the process and its main threads are collected.
3. Memory is allocated in the process (`VirtualAllocEx`) and the payload is written to it (`WriteProcessMemory`).
4. Our payload is queued as an APC via `QueueUserAPC` and the thread is resumed (`ResumeThread`).

Note: the payload in the code will spawn a calculator and promptly kill the newly created process.