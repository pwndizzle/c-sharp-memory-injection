# C# Memory Injection Examples

A set of scripts that demonstrate how to perform memory injection.

Some useful shellcode/dll/exe for popping calc can be found below:

https://github.com/peterferrie/win-exec-calc-shellcode

### Contents

- process-dll-injection.cs - Classic dll injection where the path to a dll on disk is injected in a running process and then loaded with a call to CreateRemoteThread passing LoadLibrary and the dll path. This code was originally posted here: http://www.codingvision.net/miscellaneous/c-inject-a-dll-into-a-process-w-createremotethread

- thread-hijack.cs - This example suspends a thread within a running process, injects shellcode in the process and redirects execution of an existing thread to the shellcode. Once the shellcode is executed the thread will continue as before.

- apc-injection-any-process.cs - APC injection using QueueAPC into a remote process. This method relies on the threads within the process entering an alertable state.

- apc-injection-new-process.cs - APC injection using QueueAPC into a newly created process. As the thread of a newly created process will be alertable its easier to trigger APC usage with this technique, although you will generate a new process.
