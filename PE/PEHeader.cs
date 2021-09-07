using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.IO;

namespace PE
{

    public partial class PEHeader
    {
        #region Consts

        public const int PARAGRAPH_SIZE = 0x10; // 16bytes


        public const int IMAGE_DOS_SIGNATURE      = 0x5A4D;      /* MZ */
        public const int IMAGE_NT_SIGNATURE       = 0x00004550;  /* PE00 */



        private static readonly int IMAGE_DOS_HEADER_SIZE = Marshal.SizeOf(typeof(IMAGE_DOS_HEADER));
        private static readonly int IMAGE_DATA_DIRECTORY_SIZE = Marshal.SizeOf(typeof(IMAGE_DATA_DIRECTORY));
        private static readonly int IMAGE_OPTIONAL_HEADER32_SIZE = Marshal.SizeOf(typeof(IMAGE_OPTIONAL_HEADER32));
        private static readonly int IMAGE_OPTIONAL_HEADER64_SIZE = Marshal.SizeOf(typeof(IMAGE_OPTIONAL_HEADER64));
        private static readonly int IMAGE_FILE_HEADER_SIZE = Marshal.SizeOf(typeof(IMAGE_FILE_HEADER));
        private static readonly int IMAGE_SECTION_HEADER_SIZE = Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));
        private static readonly int IMAGE_DEBUG_DIRECTORY_SIZE = Marshal.SizeOf(typeof(IMAGE_DEBUG_DIRECTORY));
        private static readonly int IMAGE_EXPORT_DIRECTORY_SIZE = Marshal.SizeOf(typeof(IMAGE_EXPORT_DIRECTORY));
        private static readonly int IMAGE_IMPORT_DESCRIPTOR_SIZE = Marshal.SizeOf(typeof(IMAGE_IMPORT_DESCRIPTOR));
        private static readonly int IMAGE_RESOURCE_DIRECTORY_SIZE = Marshal.SizeOf(typeof(IMAGE_RESOURCE_DIRECTORY));

        private static readonly int IMAGE_LOADCONFIG32_DIRECTORY_SIZE = Marshal.SizeOf(typeof(IMAGE_LOAD_CONFIG_DIRECTORY32));
        private static readonly int IMAGE_LOADCONFIG64_DIRECTORY_SIZE = Marshal.SizeOf(typeof(IMAGE_LOAD_CONFIG_DIRECTORY64));

        public static readonly uint IMAGE_ORDINAL_FLAG32 = 0x80000000;
        public static readonly ulong IMAGE_ORDINAL_FLAG64 = 0x8000000000000000;

        public static readonly ulong DEFAULT_SECURITY_COOKIE32_VALUE = 0xBB40E64E;
        public static readonly ulong DEFAULT_SECURITY_COOKIE64_VALUE = 0x2B992DDFA232;

        #endregion Consts

        #region File Header Structures


        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER        // DOS .EXE header
        {
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
            public SubSystemType Subsystem;
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
            public SubSystemType Subsystem;
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
            public Characteristics Characteristics;
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
                get
                {
                    return new string(Name).TrimEnd('\0');
                }
            }
        }


        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_DEBUG_DIRECTORY
        {
            [FieldOffset(0)]
            public UInt32  Characteristics;
            [FieldOffset(4)]
            public UInt32  TimeDateStamp;
            [FieldOffset(8)]
            public UInt16  MajorVersion;
            [FieldOffset(10)]
            public UInt16  MinorVersion;
            [FieldOffset(12)]
            public UInt32  Type;
            [FieldOffset(16)]
            public UInt32  SizeOfData;
            [FieldOffset(20)]
            public UInt32  AddressOfRawData;
            [FieldOffset(24)]
            public UInt32  PointerToRawData;

            public DateTime TimeStamp
            {
                get
                {
                    // Timestamp is a date offset from 1970
                    DateTime returnValue = new DateTime(1970, 1, 1, 0, 0, 0);

                    // Add in the number of seconds since 1970/1/1
                    returnValue = returnValue.AddSeconds(TimeDateStamp);
                    // Adjust to local timezone
                    returnValue += TimeZoneInfo.Local.GetUtcOffset(returnValue); //TimeZone.CurrentTimeZone.GetUtcOffset(returnValue);

                    return returnValue;
                }
            }

        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
        public struct IMAGE_PDB_INFO
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            private byte[] dbg_Signature;
            public Guid dbg_Guid;
            public uint dbg_Age;
            //This is bad because what if we read past the structure and it ends?
            //W/e fix this properly if it actually breaks
            //Prob end up using binaryreader or something
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 260)]
            private byte[] dbg_Name;


            public string DbgPDBPath
            {
                get
                {
                    //Read up to NULL terminator
                    string str = string.Empty;
                    for (int i = 0; i < dbg_Name.Length; i++)
                    {
                        byte b = dbg_Name[i];
                        if (b == 0)
                        {
                            break;
                        }

                        str += ((char)b).ToString();
                    }

                    return str;
                }
            }

            public string Signature
            {
                get
                {
                    return Encoding.ASCII.GetString(dbg_Signature);
                }
            }

            public bool isValid
            {
                get
                {
                    if (Signature == "RSDS")
                        return true;
                    else
                        return false;
                }
            }

        };


        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_EXPORT_DIRECTORY
        {
            public UInt32 Characteristics;
            public UInt32 TimeDateStamp;
            public UInt16 MajorVersion;
            public UInt16 MinorVersion;
            public UInt32 Name;
            public UInt32 Base;
            public UInt32 NumberOfFunctions;
            public UInt32 NumberOfNames;
            public UInt32 AddressOfFunctions;
            public UInt32 AddressOfNames;
            public UInt32 AddressOfOrdinals;

            public DateTime TimeStamp
            {
                get
                {
                    // Timestamp is a date offset from 1970
                    DateTime returnValue = new DateTime(1970, 1, 1, 0, 0, 0);

                    // Add in the number of seconds since 1970/1/1
                    returnValue = returnValue.AddSeconds(TimeDateStamp);
                    // Adjust to local timezone
                    returnValue += TimeZoneInfo.Local.GetUtcOffset(returnValue); //TimeZone.CurrentTimeZone.GetUtcOffset(returnValue);

                    return returnValue;
                }
            }

        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_IMPORT_DESCRIPTOR
        {
            public uint OriginalFirstThunk;
            public uint TimeDateStamp;
            public uint ForwarderChain;
            public uint Name;
            public uint FirstThunkPtr;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_RESOURCE_DIRECTORY
        {
            public uint Characteristics;
            public uint TimeDateStamp;
            public ushort MajorVersion;
            public ushort MinorVersion;
            public ushort NumberOfNamedEntries;
            public ushort NumberOfIdEntries;
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_LOAD_CONFIG_DIRECTORY32
        {
            public UInt32 Size;
            public UInt32 TimeDateStamp;
            public UInt16 MajorVersion;
            public UInt16 MinorVersion;
            public UInt32 GlobalFlagsClear;
            public UInt32 GlobalFlagsSet;
            public UInt32 CriticalSectionDefaultTimeout;
            public UInt32 DeCommitFreeBlockThreshold;
            public UInt32 DeCommitTotalFreeThreshold;
            public UInt32 LockPrefixTable;                // VA
            public UInt32 MaximumAllocationSize;
            public UInt32 VirtualMemoryThreshold;
            public UInt32 ProcessHeapFlags;
            public UInt32 ProcessAffinityMask;
            public UInt16 CSDVersion;
            public UInt16 Reserved1;
            public UInt32 EditList;                       // VA
            public UInt32 SecurityCookie;                 // VA
            public UInt32 SEHandlerTable;                 // VA
            public UInt32 SEHandlerCount;
            //public UInt32 GuardCFCheckFunctionPointer;    // VA
            //public UInt32 Reserved2;
            //public UInt32 GuardCFFunctionTable;           // VA
            //public UInt32 GuardCFFunctionCount;
            //public UInt32 GuardFlags;
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_LOAD_CONFIG_DIRECTORY64
        {
            public UInt32 Size;
            public UInt32 TimeDateStamp;
            public UInt16 MajorVersion;
            public UInt16 MinorVersion;
            public UInt32 GlobalFlagsClear;
            public UInt32 GlobalFlagsSet;
            public UInt32 CriticalSectionDefaultTimeout;
            public UInt64 DeCommitFreeBlockThreshold;
            public UInt64 DeCommitTotalFreeThreshold;
            public UInt64 LockPrefixTable; // VA
            public UInt64 MaximumAllocationSize;
            public UInt64 VirtualMemoryThreshold;
            public UInt64 ProcessAffinityMask;
            public UInt32 ProcessHeapFlags;
            public UInt16 CSDVersion;
            public UInt16 Reserved1;
            public UInt64 EditList; // VA
            public UInt64 SecurityCookie; // VA
            public UInt64 SEHandlerTable; // VA
            public UInt64 SEHandlerCount;
            //public UInt64 GuardCFCheckFunctionPointer; // VA
            //public UInt64 Reserved2;
            //public UInt64 GuardCFFunctionTable;        // VA
            //public UInt64 GuardCFFunctionCount;
            //public UInt32 GuardFlags;
        };


        public struct IMAGE_IMPORT_BY_NAME
        {
            public ushort Hint;
            public string Name;
        };

        [StructLayout(LayoutKind.Explicit), Serializable]
        public struct U1_32
        {
            [FieldOffset(0)]
            public uint ForwarderString;
            [FieldOffset(0)]
            public uint Function;
            [FieldOffset(0)]
            public uint Ordinal;
            [FieldOffset(0)]
            public uint AddressOfData;
        };

        [StructLayout(LayoutKind.Explicit), Serializable]
        public struct U1_64
        {
            [FieldOffset(0)]
            public ulong ForwarderString;
            [FieldOffset(0)]
            public ulong Function;
            [FieldOffset(0)]
            public ulong Ordinal;
            [FieldOffset(0)]
            public ulong AddressOfData;
        };

        [StructLayout(LayoutKind.Sequential), Serializable]
        public struct IMAGE_THUNK_DATA32
        {
            public U1_32 u1;
        };

        [StructLayout(LayoutKind.Sequential), Serializable]
        public struct IMAGE_THUNK_DATA64
        {
            public U1_64 u1;
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_BASE_RELOCATION
        {
            public uint VirtualAddress;
            public uint SizeOfBlock;
            //  WORD    TypeOffset[1];
        };





        [Flags]
        public enum DataSectionFlags : uint
        {
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeReg = 0x00000000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeDsect = 0x00000001,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeNoLoad = 0x00000002,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeGroup = 0x00000004,
            /// <summary>
            /// The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
            /// </summary>
            TypeNoPadded = 0x00000008,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeCopy = 0x00000010,
            /// <summary>
            /// The section contains executable code.
            /// </summary>
            ContentCode = 0x00000020,
            /// <summary>
            /// The section contains initialized data.
            /// </summary>
            ContentInitializedData = 0x00000040,
            /// <summary>
            /// The section contains uninitialized data.
            /// </summary>
            ContentUninitializedData = 0x00000080,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            LinkOther = 0x00000100,
            /// <summary>
            /// The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
            /// </summary>
            LinkInfo = 0x00000200,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeOver = 0x00000400,
            /// <summary>
            /// The section will not become part of the image. This is valid only for object files.
            /// </summary>
            LinkRemove = 0x00000800,
            /// <summary>
            /// The section contains COMDAT data. For more information, see section 5.5.6, COMDAT Sections (Object Only). This is valid only for object files.
            /// </summary>
            LinkComDat = 0x00001000,
            /// <summary>
            /// Reset speculative exceptions handling bits in the TLB entries for this section.
            /// </summary>
            NoDeferSpecExceptions = 0x00004000,
            /// <summary>
            /// The section contains data referenced through the global pointer (GP).
            /// </summary>
            RelativeGP = 0x00008000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            MemPurgeable = 0x00020000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            Memory16Bit = 0x00020000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            MemoryLocked = 0x00040000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            MemoryPreload = 0x00080000,
            /// <summary>
            /// Align data on a 1-byte boundary. Valid only for object files.
            /// </summary>
            Align1Bytes = 0x00100000,
            /// <summary>
            /// Align data on a 2-byte boundary. Valid only for object files.
            /// </summary>
            Align2Bytes = 0x00200000,
            /// <summary>
            /// Align data on a 4-byte boundary. Valid only for object files.
            /// </summary>
            Align4Bytes = 0x00300000,
            /// <summary>
            /// Align data on an 8-byte boundary. Valid only for object files.
            /// </summary>
            Align8Bytes = 0x00400000,
            /// <summary>
            /// Align data on a 16-byte boundary. Valid only for object files.
            /// </summary>
            Align16Bytes = 0x00500000,
            /// <summary>
            /// Align data on a 32-byte boundary. Valid only for object files.
            /// </summary>
            Align32Bytes = 0x00600000,
            /// <summary>
            /// Align data on a 64-byte boundary. Valid only for object files.
            /// </summary>
            Align64Bytes = 0x00700000,
            /// <summary>
            /// Align data on a 128-byte boundary. Valid only for object files.
            /// </summary>
            Align128Bytes = 0x00800000,
            /// <summary>
            /// Align data on a 256-byte boundary. Valid only for object files.
            /// </summary>
            Align256Bytes = 0x00900000,
            /// <summary>
            /// Align data on a 512-byte boundary. Valid only for object files.
            /// </summary>
            Align512Bytes = 0x00A00000,
            /// <summary>
            /// Align data on a 1024-byte boundary. Valid only for object files.
            /// </summary>
            Align1024Bytes = 0x00B00000,
            /// <summary>
            /// Align data on a 2048-byte boundary. Valid only for object files.
            /// </summary>
            Align2048Bytes = 0x00C00000,
            /// <summary>
            /// Align data on a 4096-byte boundary. Valid only for object files.
            /// </summary>
            Align4096Bytes = 0x00D00000,
            /// <summary>
            /// Align data on an 8192-byte boundary. Valid only for object files.
            /// </summary>
            Align8192Bytes = 0x00E00000,
            /// <summary>
            /// The section contains extended relocations.
            /// </summary>
            LinkExtendedRelocationOverflow = 0x01000000,
            /// <summary>
            /// The section can be discarded as needed.
            /// </summary>
            MemoryDiscardable = 0x02000000,
            /// <summary>
            /// The section cannot be cached.
            /// </summary>
            MemoryNotCached = 0x04000000,
            /// <summary>
            /// The section is not pageable.
            /// </summary>
            MemoryNotPaged = 0x08000000,
            /// <summary>
            /// The section can be shared in memory.
            /// </summary>
            MemoryShared = 0x10000000,
            /// <summary>
            /// The section can be executed as code.
            /// </summary>
            MemoryExecute = 0x20000000,
            /// <summary>
            /// The section can be read.
            /// </summary>
            MemoryRead = 0x40000000,
            /// <summary>
            /// The section can be written to.
            /// </summary>
            MemoryWrite = 0x80000000
        }



        public enum SubSystemType : ushort
        {
            IMAGE_SUBSYSTEM_UNKNOWN = 0,
            IMAGE_SUBSYSTEM_NATIVE = 1,
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            IMAGE_SUBSYSTEM_XBOX = 14,
            IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16
        }


        public enum DebugType : uint
        {
            IMAGE_DEBUG_TYPE_UNKNOWN = 0,       //An unknown value that is ignored by all tools.
            IMAGE_DEBUG_TYPE_COFF = 1,          //The COFF debug information (line numbers, symbol table, and string table). This type of debug information is also pointed to by fields in the file headers.
            IMAGE_DEBUG_TYPE_CODEVIEW = 2,      //The Visual C++ debug information.
            IMAGE_DEBUG_TYPE_FPO = 3,           //The frame pointer omission (FPO) information. This information tells the debugger how to interpret nonstandard stack frames, which use the EBP register for a purpose other than as a frame pointer.
            IMAGE_DEBUG_TYPE_MISC = 4,          //The location of DBG file.
            IMAGE_DEBUG_TYPE_EXCEPTION = 5,     //A copy of .pdata section.
            IMAGE_DEBUG_TYPE_FIXUP = 6,         //Reserved.
            IMAGE_DEBUG_TYPE_OMAP_TO_SRC = 7,   //The mapping from an RVA in image to an RVA in source image.
            IMAGE_DEBUG_TYPE_OMAP_FROM_SRC = 8, //The mapping from an RVA in source image to an RVA in image.
            IMAGE_DEBUG_TYPE_BORLAND = 9,       //Reserved for Borland.
            IMAGE_DEBUG_TYPE_RESERVED10 = 10,   //Reserved.
            IMAGE_DEBUG_TYPE_CLSID = 11,        //Reserved.
            IMAGE_DEBUG_TYPE_REPRO = 16         //PE determinism or reproducibility.

        }


        /// <summary>
        /// IMAGE_FILE_HEADER.Characteristics flags
        /// </summary>
        [Flags]
        public enum Characteristics : ushort
        {
            /// <summary>Relocation info stripped from file.</summary>
            RelocsStripped = 0x0001,
            /// <summary>File is executable  (i.e. no unresolved externel references).</summary>
            ExecutableImage = 0x0002,
            /// <summary>Line nunbers stripped from file.</summary>
            LineNumsStripped = 0x0004,
            /// <summary>Local symbols stripped from file.</summary>
            LocalSymsStripped = 0x0008,
            /// <summary>Agressively trim working set</summary>
            AggressiveWsTrim = 0x0010,
            /// <summary>App can handle >2gb addresses</summary>
            LargeAddressAware = 0x0020,
            /// <summary/>
            Reserved1 = 0x0040,
            /// <summary>Bytes of machine word are reversed.</summary>
            BytesReversedLo = 0x0080,
            /// <summary>32 bit word machine.</summary>
            _32BitMachine = 0x0100,
            /// <summary>Debugging info stripped from file in .DBG file</summary>
            DebugStripped = 0x0200,
            /// <summary>If Image is on removable media, copy and run from the swap file.</summary>
            RemovableRunFromSwap = 0x0400,
            /// <summary>If Image is on Net, copy and run from the swap file.</summary>
            NetRunFromSwap = 0x0800,
            /// <summary>System File.</summary>
            System = 0x1000,
            /// <summary>File is a DLL.</summary>
            Dll = 0x2000,
            /// <summary>File should only be run on a UP machine</summary>
            UpSystemOnly = 0x4000,
            /// <summary>Bytes of machine word are reversed.</summary>
            BytesReversedHi = 0x8000,
        }

        #endregion File Header Structures

        #region Private Fields

        /// <summary>
        /// The DOS header
        /// </summary>
        private IMAGE_DOS_HEADER dosHeader;
        /// <summary>
        /// The DOS stub
        /// </summary>
        private byte[] dosStub;
        /// <summary>
        /// PE - magic
        /// </summary>
        private Int32 peMagic;
        /// <summary>
        /// The file header
        /// </summary>
        private IMAGE_FILE_HEADER fileHeader;
        /// <summary>
        /// Optional 32 bit file header
        /// </summary>
        private IMAGE_OPTIONAL_HEADER32 optionalHeader32;
        /// <summary>
        /// Optional 64 bit file header
        /// </summary>
        private IMAGE_OPTIONAL_HEADER64 optionalHeader64;
        /// <summary>
        /// Image Section headers. Number of sections is in the file header.
        /// </summary>
        private IMAGE_SECTION_HEADER[] imageSectionHeaders;
        /// <summary>
        /// Image Debug Directory contains the address and size of the executable’s debug directory
        /// </summary>
        private IMAGE_DEBUG_DIRECTORY imageDebugDirectory;

        /// <summary>
        /// Image Export Directory contains the exported functions exposed by the PE image
        /// </summary>
        private IMAGE_EXPORT_DIRECTORY imageExportDirectory;

     
        private long headerEndPosition;
        private long fileSize;


        #endregion Private Fields

        #region Public Methods

        public PEHeader()
        {
        }

        public PEHeader(PEHeader pe_copy)
        {
            //This is missing some elements
            this.dosHeader = pe_copy.dosHeader;
            this.dosStub = pe_copy.dosStub;
            this.peMagic = pe_copy.peMagic;
            this.fileHeader = pe_copy.fileHeader;
            this.optionalHeader32 = pe_copy.optionalHeader32;
            this.optionalHeader64 = pe_copy.optionalHeader64;
            this.imageSectionHeaders = new IMAGE_SECTION_HEADER[pe_copy.imageSectionHeaders.Length];
            Array.Copy(pe_copy.imageSectionHeaders, this.imageSectionHeaders, pe_copy.imageSectionHeaders.Length);
            this.imageDebugDirectory = pe_copy.imageDebugDirectory;
            this.imageExportDirectory = pe_copy.imageExportDirectory;
            this.headerEndPosition = pe_copy.headerEndPosition;
            this.fileSize = pe_copy.fileSize;
        }

        /// <summary>
        /// Reads in a block from a file and converts it to the struct
        /// type specified by the template parameter
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="reader"></param>
        /// <returns></returns>
        public static T FromBinaryReader<T>(BinaryReader reader) where T : struct
        {
            // Read in a byte array
            byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));
            T theStructure = ByteArrayToStructure<T>(bytes);
            return theStructure;
        }

        public static PEHeader Load(string path)
        {
            PEHeader h = new PEHeader();
            bool load_result = h.LoadPEHeader(path);
            if (!load_result)
                return null;
            else
                return h;
        }

        public static PEHeader Load(byte[] data)
        {
            PEHeader h = new PEHeader();
            bool load_result = h.LoadPEHeader(data);
            if (!load_result)
                return null;
            else
                return h;
        }

        #endregion Public Methods

        #region Other Public Methods

        public bool LoadPEHeader(byte[] raw)
        {
            return ReadIn(raw);
        }

        public bool LoadPEHeader(string filePath)
        {
            return ReadIn(File.ReadAllBytes(filePath));
        }

        public void SetupRelocation(IntPtr imageBase)
        {
            if (Is32BitHeader)
            {
                optionalHeader32.ImageBase = (UInt32)imageBase;
            }
            else
            {
                optionalHeader64.ImageBase = (UInt64)imageBase;
            }
        }

        #endregion Other Public Methods

        #region Properties

        /// <summary>
        /// Returns the DOS header
        /// </summary>
        public IMAGE_DOS_HEADER DOSHeader
        {
            get
            {
                return dosHeader;
            }
            set
            {
                dosHeader = value;
            }
        }

        public byte[] DOSStub
        {
            get
            {
                return dosStub;
            }
        }

        /// <summary>
        /// Gets if the file header is 32 bit or not
        /// </summary>
        public bool Is32BitHeader
        {
            get
            {
                return (Characteristics._32BitMachine & FileHeader.Characteristics) == Characteristics._32BitMachine;
            }
        }

        public bool Is64BitHeader
        {
            get
            {
                return !Is32BitHeader;
            }
        }

        public bool IsValid
        {
            //TODO: Check other stuff too!
            get
            {
                if (dosHeader.e_magic == IMAGE_DOS_SIGNATURE && peMagic == IMAGE_NT_SIGNATURE)
                    return true;
                else
                    return false;
            }
        }

        public bool IsDLL
        {
            get
            {
                return (Characteristics.Dll & FileHeader.Characteristics) == Characteristics.Dll;
            }
        }

        /// <summary>
        /// Gets the file header
        /// </summary>
        public IMAGE_FILE_HEADER FileHeader
        {
            get
            {
                return fileHeader;
            }
            set
            {
                fileHeader = value;
            }
        }

        /// <summary>
        /// Gets the optional header
        /// </summary>
        public IMAGE_OPTIONAL_HEADER32 OptionalHeader32
        {
            get
            {
                return optionalHeader32;
            }
            set
            {
                optionalHeader32 = value;
            }
        }

        /// <summary>
        /// Gets the optional header
        /// </summary>
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader64
        {
            get
            {
                return optionalHeader64;
            }
            set
            {
                optionalHeader64 = value;
            }
        }

        public IMAGE_SECTION_HEADER[] ImageSectionHeaders
        {
            get
            {
                return imageSectionHeaders;
            }
            set
            {
                imageSectionHeaders = value;
            }
        }

        /// <summary>
        /// Gets the timestamp from the file header
        /// </summary>
        public DateTime TimeStamp
        {
            get
            {
                // Timestamp is a date offset from 1970
                DateTime returnValue = new DateTime(1970, 1, 1, 0, 0, 0);

                // Add in the number of seconds since 1970/1/1
                returnValue = returnValue.AddSeconds(fileHeader.TimeDateStamp);
                // Adjust to local timezone
                returnValue += TimeZoneInfo.Local.GetUtcOffset(returnValue); //TimeZone.CurrentTimeZone.GetUtcOffset(returnValue);

                return returnValue;
            }
        }

        public IMAGE_DEBUG_DIRECTORY DebugDirectory
        {
            get
            {
                return imageDebugDirectory;
            }
        }

        public IMAGE_EXPORT_DIRECTORY ExportDirectory
        {
            get
            {
                return imageExportDirectory;
            }
        }

        public long EOHPointer
        {
            get
            {
                return headerEndPosition;
            }
        }

        public long FileSize
        {
            get
            {
                return fileSize;
            }
        }

        public dynamic OptionalHeader
        {
            get
            {
                if (Is32BitHeader)
                    return optionalHeader32;
                else
                    return optionalHeader64;
            }
        }

        #endregion Properties

        #region Private Methods

        private bool ReadIn(byte[] data)
        {
            using (MemoryStream stream = new MemoryStream(data))
            {
                BinaryReader reader = new BinaryReader(stream);
                fileSize = stream.Length;
                dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);

                int dos_stub_size = (Int32)(dosHeader.e_lfanew - (dosHeader.e_cparhdr * PARAGRAPH_SIZE));
                if (dos_stub_size > 0)
                {
                    dosStub = reader.ReadBytes(dos_stub_size);
                }
                else
                {
                    dosStub = new byte[0];
                }

                //seek to PE (don't really need to do this)
                stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);

                peMagic = reader.ReadInt32();
                if (peMagic != IMAGE_NT_SIGNATURE) //PE00
                {
                    return false;
                }

                fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);
                if (this.Is32BitHeader)
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

                headerEndPosition = reader.BaseStream.Position;

                //Read each data directory
                ReadSection_ExportTable_br(reader);


            } //end using memoryreader

            return true;
        }


        /**
        *	\!roundup
        *	round a value to "base"
        **/
        public UInt32 RoundUp(uint value, uint base_address)
        {
            UInt32 tmpValue = value;

            if (base_address == 0)
            {
                Console.WriteLine("Error: Address 0x" + value.ToString("X") + " for base 0x" + base_address.ToString("X"));
                return value;
            }

            while((tmpValue % base_address) != 0)
                tmpValue++;
            return tmpValue;
        }


        /**
        *	\!	round_section
        *	return "value" aligned to "SectionAlignment" of PE
        **/
        public UInt32 RoundSection(uint value)
        {
            uint section_alignment = 0;
            if (Is32BitHeader)
                section_alignment = optionalHeader32.SectionAlignment;
            else
                section_alignment = optionalHeader64.SectionAlignment;

            return RoundUp(value, section_alignment);
        }

        /**
         *	\!	round_file
         *	return "value" aligned to "FileAlignment" of PE
         **/
        public UInt32 RoundFile(uint value)
        {
            uint file_alignment = 0;
            if (Is32BitHeader)
                file_alignment = optionalHeader32.FileAlignment;
            else
                file_alignment = optionalHeader64.FileAlignment;
            return RoundUp(value, file_alignment);
        }



        public UInt32 GetRealSectionSize(PEHeader.IMAGE_SECTION_HEADER hdr)
        {
            UInt32 size = hdr.SizeOfRawData;
            if (size == 0)
            {
                if (hdr.Characteristics.HasFlag(DataSectionFlags.ContentInitializedData))
                {
                    if (Is64BitHeader)
                        size = OptionalHeader64.SizeOfInitializedData;
                    else
                        size = OptionalHeader32.SizeOfInitializedData;
                }
                else if (hdr.Characteristics.HasFlag(DataSectionFlags.ContentUninitializedData))
                {
                    if (Is64BitHeader)
                        size = OptionalHeader64.SizeOfUninitializedData;
                    else
                        size = OptionalHeader32.SizeOfUninitializedData;
                }
            }
            return size;
        }


        public int GetSectionIndexForRVA(UInt32 RVA)
        {
            // Look up the section the RVA belongs to
            int section_idx = -1;
            for (int i = 0; i < imageSectionHeaders.Length; i++)
            {
                IMAGE_SECTION_HEADER current_section_header = imageSectionHeaders[i];
                UInt32 SectionSize = current_section_header.VirtualSize;

                if ((RVA >= current_section_header.VirtualAddress) &&
                        (RVA < current_section_header.VirtualAddress + SectionSize))
                {
                    // Yes, the RVA belongs to this section
                    section_idx = i;
                    break;
                }
            }
            return section_idx;
        }

        public int GetSectionIndexForRVA(UInt64 RVA)
        {
            // Look up the section the RVA belongs to
            int section_idx = -1;
            for (int i = 0; i < imageSectionHeaders.Length; i++)
            {
                IMAGE_SECTION_HEADER current_section_header = imageSectionHeaders[i];
                UInt32 SectionSize = current_section_header.VirtualSize;

                if ((RVA >= current_section_header.VirtualAddress) &&
                        (RVA < current_section_header.VirtualAddress + SectionSize))
                {
                    // Yes, the RVA belongs to this section
                    section_idx = i;
                    break;
                }
            }
            return section_idx;
        }


        public UInt32 GetFileOffsetFromRVA(UInt32 RVA)
        {
            UInt32 file_offset = 0xFFFFFFFF;

            // Look up the section the RVA belongs to

            bool bFound = false;
            IMAGE_SECTION_HEADER found_section = new IMAGE_SECTION_HEADER();

            for (int i = 0; i < imageSectionHeaders.Length; i++)
            {
                IMAGE_SECTION_HEADER current_section_header = imageSectionHeaders[i];
                UInt32 SectionSize = current_section_header.VirtualSize;

                if ((RVA >= current_section_header.VirtualAddress) &&
                        (RVA < current_section_header.VirtualAddress + SectionSize))
                {
                    // Yes, the RVA belongs to this section
                    bFound = true;
                    found_section = current_section_header;
                    break;
                }
            }

            if (!bFound)
            {
                // Section not found
                return file_offset;
            }

            // Look up the file offset using the section header

            UInt32 Diff = (UInt32)(found_section.VirtualAddress - found_section.PointerToRawData);
            file_offset = RVA - Diff;


            // Complete
            return file_offset;
        }

        public UInt64 GetFileOffsetFromRVA(UInt64 RVA)
        {
            UInt64 file_offset = 0xFFFFFFFFFFFFFFFF;

            // Look up the section the RVA belongs to

            bool bFound = false;
            IMAGE_SECTION_HEADER found_section = new IMAGE_SECTION_HEADER();

            for (int i = 0; i < imageSectionHeaders.Length; i++)
            {
                IMAGE_SECTION_HEADER current_section_header = imageSectionHeaders[i];
                UInt32 SectionSize = current_section_header.VirtualSize;

                if ((RVA >= current_section_header.VirtualAddress) &&
                        (RVA < current_section_header.VirtualAddress + SectionSize))
                {
                    // Yes, the RVA belongs to this section
                    bFound = true;
                    found_section = current_section_header;
                    break;
                }
            }

            if (!bFound)
            {
                // Section not found
                return file_offset;
            }

            // Look up the file offset using the section header

            UInt32 Diff = (UInt32)(found_section.VirtualAddress - found_section.PointerToRawData);
            file_offset = RVA - Diff;


            // Complete
            return file_offset;
        }

        public UInt32 GetRVAFromOffset(UInt32 offset)
        {
            UInt32 rva = 0xFFFFFFFF;

            // Look up the section the file offset belongs to
            bool bFound = false;
            IMAGE_SECTION_HEADER found_section = new IMAGE_SECTION_HEADER();

            for (int i = 0; i < imageSectionHeaders.Length; i++)
            {
                IMAGE_SECTION_HEADER current_section_header = imageSectionHeaders[i];

                if ((offset >= current_section_header.PointerToRawData) && (offset <= current_section_header.PointerToRawData + current_section_header.SizeOfRawData))
                {
                    // Yes, the RVA belongs to this section
                    bFound = true;
                    found_section = current_section_header;
                    break;
                }
            }

            if (!bFound)
            {
                // Section not found
                return rva;
            }

            // Calc Delta
            UInt32 Diff = (UInt32)(offset - found_section.PointerToRawData);
            rva = found_section.VirtualAddress + Diff;

            // Complete
            return rva;
        }

        public byte[] StructureToByteArray<T>(T strc) where T : struct
        {
            int objsize = Marshal.SizeOf(typeof(T));
            byte[] pBuffer = new byte[objsize];

            IntPtr ptr = Marshal.AllocHGlobal(objsize);
            Marshal.StructureToPtr(strc, ptr, true);
            Marshal.Copy(ptr, pBuffer, 0, objsize);
            Marshal.FreeHGlobal(ptr);
            return pBuffer;
        }

        public static T ByteArrayToStructure<T>(byte[] byteData) where T : struct
        {
            byte[] buffer = byteData;
            GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            T data = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();
            return data;
        }



        #endregion Private Methods
    }
}