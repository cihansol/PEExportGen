using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Diagnostics;


namespace PE
{
    public partial class PEImage
    {
        public class SectionData
        {
            public int idx;
            public PEHeader.IMAGE_SECTION_HEADER hdr;
            public byte[] data;
            public string Name;

            public SectionData()
            {
                Name = "";
            }

            public SectionData(int index, PEHeader.IMAGE_SECTION_HEADER in_hdr, byte[] in_data)
            {
                idx = index;
                hdr = in_hdr;
                Name = in_hdr.Section;
                data = new byte[in_data.Length];
                Array.Copy(in_data, data, in_data.Length);
            }

            public UInt32 ToRVA(UInt32 VA)
            {
                return VA - hdr.VirtualAddress;
            }

            public UInt64 ToRVA(UInt64 VA)
            {
                return VA - hdr.VirtualAddress;
            }

        }

        public class ExportModule
        {
            public string Name;
            public List<Export> exports;


            public int FunctionCount
            {
                get
                {
                    return exports.Count;
                }
            }

            public ExportModule()
            {
                Name = string.Empty;
                exports = new List<Export>();
            }


            [DebuggerDisplay("ID = {idx} Name = {Name}")]
            public class Export
            {
                public int idx;
                public UInt32 NameRVA;
                public string Name;
                public uint FuncAddress;
                public uint Ordinal;
                public int NameOrdinal;
                public bool bIsForwarded;
                public bool bIsMSApiForward;
                public bool bIsBadOrNullExport;
                public string ForwardedSignature;
                public UInt32 ForwardedSignatureRVA;

                //Only for forwarded exports
                public string forwarded_module;
                public string forwarded_function;
                public UInt16 forwarded_ordinal;

                public Export()
                {
                    idx = -1;
                    Name = string.Empty;
                    FuncAddress = 0xFFFFFFFF;
                    Ordinal = 0;
                    NameOrdinal = 0;
                    bIsForwarded = false;
                    bIsMSApiForward = false;
                    bIsBadOrNullExport = false;
                }



            }
        }

        public class Relocation
        {
            private PEHeader.IMAGE_BASE_RELOCATION _reloc;

            public class Item
            {
                public enum Type : uint
                {
                    IMAGE_REL_BASED_ABSOLUTE = 0,
                    IMAGE_REL_BASED_HIGH = 1,
                    IMAGE_REL_BASED_LOW = 2,
                    IMAGE_REL_BASED_HIGHLOW = 3,
                    IMAGE_REL_BASED_HIGHADJ = 4,
                    IMAGE_REL_BASED_MACHINE_SPECIFIC_5 = 5,
                    IMAGE_REL_BASED_RESERVED = 6,
                    IMAGE_REL_BASED_MACHINE_SPECIFIC_7 = 7,
                    IMAGE_REL_BASED_MACHINE_SPECIFIC_8 = 8,
                    IMAGE_REL_BASED_MACHINE_SPECIFIC_9 = 9,
                    IMAGE_REL_BASED_DIR64 = 10
                }

                public UInt16 item;
                public UInt32 item_va;
                public UInt32 item_of;
                public Type reloc_type;

                public Item()
                {

                }

                public Item(ushort itm, uint itm_va, uint itm_of, Type itm_reloc_type)
                {
                    item = itm;
                    item_va = itm_va;
                    item_of = itm_of;
                    reloc_type = itm_reloc_type;
                }

            }

            public uint VA;
            public uint SizeOfBlock; //datasize
            public List<Item> Items;

            public Relocation()
            {

            }

            public Relocation(PEHeader.IMAGE_BASE_RELOCATION reloc, List<Item> items)
            {
                _reloc = reloc;
                VA = reloc.VirtualAddress;
                SizeOfBlock = reloc.SizeOfBlock;
                Items = new List<Item>(items);
            }


        }
    }
}
