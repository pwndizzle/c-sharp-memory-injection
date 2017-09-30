# C# Memory Injection Examples

A set of scripts that demonstrate how to perform memory injection.

### Contents

- thread-hijack.cs - This example suspends a thread within a running process, injects shellcode in the process and redirects execution of an existing thread to the shellcode. Once the shellcode is executed the thread will continue as before.
