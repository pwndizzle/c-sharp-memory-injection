# C# Memory Injection Examples

A set of scripts that demonstrate how to perform memory injection.

I've tried to make these techniques as simple and opsec safe as possible, avoiding unnecessary memory modifications, process or file creation. I'm no C# expert or memory injection guru so use these examples at your own risk :)

The shellcode used in the examples can be found below (there are also dll/exe versions too): 

https://github.com/peterferrie/win-exec-calc-shellcode

### Contents

- apc-injection-any-process.cs - APC injection using QueueAPC into a currently running remote process. This method relies on the threads within the process entering an alertable state.

- apc-injection-new-process.cs - APC injection using QueueAPC into a newly created process. As the threads of a newly created process will be alertable its easier to trigger APC usage with this technique, although you will generate a new process.

- iat-injection.cs - Modify a specific import pointer for a target function within a specific process to point to shellcode before continuing to execute the legitimate function.

- process-dll-injection.cs - Classic dll injection where the path to a dll on disk is injected in a running process and then loaded with a call to CreateRemoteThread passing LoadLibrary and the dll path.

- thread-hijack.cs - This example suspends a thread within a running process, injects shellcode in the process and redirects execution of an existing thread to the shellcode. Once the shellcode is executed the thread will continue as before.


