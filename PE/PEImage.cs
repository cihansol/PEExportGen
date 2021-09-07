using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;


namespace PE
{
    public partial class PEImage
    {

        private const string API_SET_PREFIX_NAME = "api-";
        private const string API_SET_EXTENSION_NAME = "ext-";

        private bool bLoaded; //image is loaded
        private MemoryStream _base; //underlying buffer for the PEImage

        private PEHeader header;
        private List<SectionData> section_data;
        private byte[] overlay_data;
        private ExportModule export_module;
        private List<Relocation> relocations;


        public PEHeader Header
        {
            get
            {
                return header;
            }
        }

        public bool IsValid
        {
            get
            {
                return header.IsValid;
            }
        }

        public bool IsDLL
        {
            get
            {
                return header.IsDLL;
            }
        }

        public bool isLoaded
        {
            get
            {
                return bLoaded;
            }
        }

        public bool is32BitImage
        {
            get
            {
                return header.Is32BitHeader;
            }
        }

        public bool is64BitImage
        {
            get
            {
                return header.Is64BitHeader;
            }
        }

        public ExportModule Exports
        {
            get
            {
                return export_module;
            }
        }

        public List<SectionData> Sections
        {
            get
            {
                return section_data;
            }
            set
            {
                section_data = new List<SectionData>(value);
            }
        }

        public IntPtr ImageBase
        {
            get
            {
                IntPtr imgbase = IntPtr.Zero;
                if (header.Is64BitHeader)
                {
                    imgbase = new IntPtr((long)header.OptionalHeader64.ImageBase);
                }
                else
                {
                    imgbase = new IntPtr((int)header.OptionalHeader32.ImageBase);
                }
                return imgbase;
            }
        }


        public PEImage()
        {
            header = new PEHeader();
            section_data = new List<SectionData>();
            relocations = new List<Relocation>();
        }


        public bool Load(string filepath)
        {
            return Load(File.ReadAllBytes(filepath));
        }

        public bool Load(byte[] data)
        {
            _base = new MemoryStream(data);
            bLoaded = header.LoadPEHeader(data);
            if (!bLoaded)
            {
                header = null; //header is invalid set it to NULL
                _base.Close();
                return false;
            }

            using (BinaryReader br = new BinaryReader(_base))
            {
                //Load core of sections into buffer
                bLoaded = InternalReadData(br);

                //Load core of pe image here
                bLoaded = InternalLoad(br);
            }

            return bLoaded;
        }

        public static PEImage LoadPE(string path)
        {
            PEImage img = new PEImage();
            bool load_result = img.Load(path);
            if (!load_result)
                return null;
            else
                return img;
        }

        public static PEImage LoadPE(byte[] data)
        {
            PEImage img = new PEImage();
            bool load_result = img.Load(data);
            if (!load_result)
                return null;
            else
                return img;
        }


        public bool RelocateImage(IntPtr imageBase)
        {
            return pe_relocateImage(imageBase);
        }


        //On Disk
        private bool InternalLoad(BinaryReader br)
        {
            //Read Exports
            ld_exports(br);

            return true;
        }



        private bool InternalReadData(BinaryReader br)
        {
            long header_end = header.EOHPointer;
            long read_size = 0;
            for (int s = 0; s < header.ImageSectionHeaders.Length; s++)
            {
                PEHeader.IMAGE_SECTION_HEADER section_head = header.ImageSectionHeaders[s];
                br.BaseStream.Seek(section_head.PointerToRawData, SeekOrigin.Begin);
                byte[] data = br.ReadBytes((int)section_head.SizeOfRawData);
                read_size += data.Length;
                section_data.Add(new SectionData(s, section_head, data));
            }

            PEHeader.IMAGE_SECTION_HEADER last_section = header.ImageSectionHeaders[header.ImageSectionHeaders.Length - 1];
            long dif = header.FileSize - (last_section.PointerToRawData + last_section.SizeOfRawData);
            if (dif > 0)
            {
                //we have overlay it seems :)
                br.BaseStream.Seek(last_section.PointerToRawData + last_section.SizeOfRawData, SeekOrigin.Begin);
                overlay_data = br.ReadBytes((int)dif);
            }
            return true;
        }

 
        //Disk based
        private void ld_exports(BinaryReader br)
        {
            //Check if the export directory exists?
            if (header.ExportDirectory.AddressOfFunctions == 0 && header.ExportDirectory.AddressOfNames == 0 && header.ExportDirectory.AddressOfOrdinals == 0)
                return;


            UInt32 exportTable_start = 0;
            UInt32 exportTable_end = 0xFFFFFFFF;

            if (header.Is32BitHeader)
            {
                exportTable_start = header.OptionalHeader32.ExportTable.VirtualAddress;
                exportTable_end = exportTable_start + header.OptionalHeader32.ExportTable.Size;
            }
            else
            {
                exportTable_start = header.OptionalHeader64.ExportTable.VirtualAddress;
                exportTable_end = exportTable_start + header.OptionalHeader64.ExportTable.Size;
            }


            //Setup the export module
            export_module = new ExportModule();
            export_module.Name = ReadASCIIZstring(br, ToFileOffset(header.ExportDirectory.Name));

            UInt32 pAddressPtr = ToFileOffset(header.ExportDirectory.AddressOfFunctions);
            UInt32 pNamePtr = ToFileOffset(header.ExportDirectory.AddressOfNames);
            UInt32 pOrdinalPtr = ToFileOffset(header.ExportDirectory.AddressOfOrdinals);

            // Make tiny array to mark if an ordinal was processed.
            bool[] processed = new bool[header.ExportDirectory.NumberOfFunctions];

            Int32 ptrSize = sizeof(int); //pe internal ptr size (4byte) not 8

            //handle Names
            for (int i = 0; i < header.ExportDirectory.NumberOfNames; i++)
            {
                ExportModule.Export exp = new PEImage.ExportModule.Export();
                exp.idx = -1; //set for now (change later to ordinal)


                //----Name
                //Get the string pointer location
                UInt32 currentNameStrPtr = pNamePtr + (uint)(i * ptrSize);
                //Seek to the pointer
                br.BaseStream.Seek(currentNameStrPtr, SeekOrigin.Begin);
                //Read the pointer (RVA)
                exp.NameRVA = br.ReadUInt32();
                //RVA -> File offset
                UInt32 currentNamePtr_fo = ToFileOffset(exp.NameRVA);
                //Read
                exp.Name = ReadASCIIZstring(br, currentNamePtr_fo);

                //----Ordinal
                UInt32 currentOrdinalPtr = pOrdinalPtr + (uint)i * 2; //2bytes
                //Seek to the pointer
                br.BaseStream.Seek(currentOrdinalPtr, SeekOrigin.Begin);
                //Read the value (RVA)
                exp.Ordinal = br.ReadUInt16();
                exp.idx = (int)exp.Ordinal; //Set IDX before we add base
                exp.NameOrdinal = (int)exp.Ordinal; //Set Name ordinal
                exp.Ordinal = exp.Ordinal + header.ExportDirectory.Base; //Add Base


                //----Function Address
                UInt32 currentAddressPtr = pAddressPtr + (uint)(exp.NameOrdinal * ptrSize);
                //Seek to the pointer
                br.BaseStream.Seek(currentAddressPtr, SeekOrigin.Begin);
                //Read the value (RVA)
                exp.FuncAddress = br.ReadUInt32();

                if (exp.FuncAddress >= exportTable_start && exp.FuncAddress < exportTable_end)
                {
                    //Forwarded function
                    exp.ForwardedSignatureRVA = exp.FuncAddress;
                    exp.FuncAddress = 0xFFFFFFFF;
                    exp.bIsForwarded = true;

                    //Read the signature
                    exp.ForwardedSignature = ReadASCIIZstring(br, ToFileOffset(exp.ForwardedSignatureRVA));

                    //Set forwarded module
                    exp.forwarded_module = exp.ForwardedSignature.Substring(0, exp.ForwardedSignature.LastIndexOf('.')) + ".dll";

                    //Set forwarded function
                    //get function name (could be ordinal)
                    int index = exp.ForwardedSignature.LastIndexOf('.') + 1;
                    exp.forwarded_function = exp.ForwardedSignature.Substring(index, exp.ForwardedSignature.Length - index);

                    //check if its an ordinal
                    if (exp.forwarded_function.Contains("#"))
                    {

                        //Following # is a digit or not?
                        int hash_index = exp.forwarded_function.IndexOf('#');
                        if (exp.forwarded_function.Substring(hash_index + 1).All(Char.IsDigit))
                        {
                            exp.forwarded_ordinal = UInt16.Parse(exp.forwarded_function.Substring(hash_index + 1));
                            exp.forwarded_function = string.Empty; //if string "" use ordinal
                        }
                        else
                        {
                            exp.bIsBadOrNullExport = true; //?? Not implemented
                            exp.forwarded_function = exp.forwarded_function.Substring(hash_index + 1);
                            exp.forwarded_ordinal = 0;
                            exp.FuncAddress = 0;
                        }

                    }

                    //check if its a Microsoft API forward
                    if (exp.forwarded_module.StartsWith(API_SET_PREFIX_NAME) || exp.forwarded_module.StartsWith(API_SET_EXTENSION_NAME))
                    {
                        exp.bIsMSApiForward = true;
                    }

                }
                else
                {
                    //Normal function
                }

                //mark processed ordinals
                processed[exp.idx] = true;

                //Add to List
                export_module.exports.Add(exp);

            } //end for loop (Name)


            //handle Ordinals
            if (pOrdinalPtr != 0xFFFFFFFF)
            {
                for (int i = 0; i < header.ExportDirectory.NumberOfFunctions; i++)
                {
                    // Check if we've already processed this ordinal.
                    if (processed[i])
                        continue;

                    ExportModule.Export exp = new PEImage.ExportModule.Export();
                    exp.idx = -1; //set for now (change later to ordinal)

                    //----Ordinal
                    UInt32 currentOrdinalPtr = pOrdinalPtr + (uint)i * 2; //2bytes
                    //Seek to the pointer
                    br.BaseStream.Seek(currentOrdinalPtr, SeekOrigin.Begin);
                    //Read the value (RVA)
                    exp.Ordinal = br.ReadUInt16();
                    exp.idx = (int)exp.Ordinal; //Set IDX before we add base
                    exp.Ordinal = exp.Ordinal + header.ExportDirectory.Base; //Add Base


                    //----Function Address
                    UInt32 currentAddressPtr = pAddressPtr + (uint)(i * ptrSize);
                    //Seek to the pointer
                    br.BaseStream.Seek(currentAddressPtr, SeekOrigin.Begin);
                    //Read the value (RVA)
                    exp.FuncAddress = br.ReadUInt32();

                    //mark processed ordinals
                    processed[i] = true;

                    //Add to List
                    export_module.exports.Add(exp);

                } //end for loop (Ordinal)
            }

            //handle ?? (Function that not exported by Name and proper ordinal but still exist)
            for (int i = 0; i < header.ExportDirectory.NumberOfFunctions; i++)
            {
                // Check if we've already processed this ordinal.
                if (processed[i])
                    continue;

                ExportModule.Export exp = new PEImage.ExportModule.Export();
                exp.idx = i; //Set IDX before we add base
                exp.Ordinal = (uint)exp.idx + header.ExportDirectory.Base; //Add Base

                //----Function Address
                UInt32 currentAddressPtr = pAddressPtr + (uint)(i * ptrSize);
                //Seek to the pointer
                br.BaseStream.Seek(currentAddressPtr, SeekOrigin.Begin);
                //Read the value (RVA)
                exp.FuncAddress = br.ReadUInt32();

                //mark processed ordinals (we don't really need to do this nothing else is going to use the array lol)
                processed[i] = true;

                //Add to List
                export_module.exports.Add(exp);
            } //end for loop (??)

        }

        //tasks

        private bool pe_relocateImage(IntPtr imageBase)
        {
            if (!bLoaded)
            {
                return false;
            }

            long reloc_delta = 0;
            if (header.Is64BitHeader)
                reloc_delta = imageBase.ToInt64() - (Int64)header.OptionalHeader64.ImageBase;
            else
                reloc_delta = imageBase.ToInt64() - (Int64)header.OptionalHeader32.ImageBase;


            if (reloc_delta == 0 || relocations.Count == 0)
            {
                //Why are we relocating??
                //Update imagebase
                header.SetupRelocation(imageBase);
                return true;
            }


            for (int r = 0; r < relocations.Count; r++)
            {
                Relocation reloc_block = relocations[r];
                SectionData reloc_secData = GetSectionDataByRVA(reloc_block.VA);
                List<Relocation.Item> items = reloc_block.Items;
                for (int i = 0; i < items.Count; i++)
                {
                    Relocation.Item item = items[i];

                    using (MemoryStream ms = new MemoryStream(reloc_secData.data))
                        using (BinaryReader br = new BinaryReader(ms))
                            using (BinaryWriter bw = new BinaryWriter(ms))
                            {
                                //Find offset
                                UInt32 offset = reloc_secData.ToRVA(item.item_va);
                                //Seek there
                                ms.Seek(offset, SeekOrigin.Begin);

                                //We only deal with x86 and x64
                                if (item.reloc_type == Relocation.Item.Type.IMAGE_REL_BASED_ABSOLUTE)
                                {
                                    continue; //No need to fix
                                }
                                else if (item.reloc_type == Relocation.Item.Type.IMAGE_REL_BASED_HIGHLOW)
                                {
                                    //x86

                                    //Read value
                                    Int32 reloc_val32 = br.ReadInt32();
                                    //Change value
                                    reloc_val32 = reloc_val32 + (Int32)reloc_delta;
                                    //Seek again
                                    ms.Seek(offset, SeekOrigin.Begin);
                                    //Write new value
                                    bw.Write(reloc_val32);

                                }
                                else if (item.reloc_type == Relocation.Item.Type.IMAGE_REL_BASED_DIR64)
                                {
                                    //x64

                                    //Read value
                                    Int64 reloc_val64 = br.ReadInt64();
                                    //Change value
                                    reloc_val64 = reloc_val64 + reloc_delta;
                                    //Seek again
                                    ms.Seek(offset, SeekOrigin.Begin);
                                    //Write new value
                                    bw.Write(reloc_val64);

                                }

                            }
                } //reloc block loop
            } //relocs loop


            //Update imagebase
            header.SetupRelocation(imageBase);



            return true;
        }

        private string ReadASCIIZstring(BinaryReader reader, uint offset = 0xFFFFFFFF)
        {
            if(offset != 0xFFFFFFFF)
                reader.BaseStream.Position = offset;

            //Read till Null terminator \0
            string str = string.Empty;
            byte b = 0;
            b = reader.ReadByte();
            while (b != 0)
            {
                str += ((char)b).ToString();
                b = reader.ReadByte();
            }
            return str;
        }

        public UInt32 ToFileOffset(UInt32 rva)
        {
            return header.GetFileOffsetFromRVA(rva);
        }

        public UInt64 ToFileOffset(UInt64 rva)
        {
            return header.GetFileOffsetFromRVA(rva);
        }

        public UInt32 ToRVA(UInt32 file_offset)
        {
            return header.GetRVAFromOffset(file_offset);
        }

        public UInt32 ToVA_x86(UInt32 file_offset)
        {
            uint rva = header.GetRVAFromOffset(file_offset);
            uint va = 0xFFFFFFFF;
            va = header.OptionalHeader32.ImageBase + rva;
            return va;
        }

        public UInt64 ToVA_x64(UInt32 file_offset)
        {
            uint rva = header.GetRVAFromOffset(file_offset);
            UInt64 va = 0xFFFFFFFF;
            va = header.OptionalHeader64.ImageBase + rva;
            return va;
        }

        public SectionData GetSectionDataByRVA(UInt32 rva)
        {
            SectionData data = null;
            int index = header.GetSectionIndexForRVA(rva);
            if (index != -1)
                data = section_data[index];
            return data;
        }

        public SectionData GetSectionDataByRVA(UInt64 rva)
        {
            SectionData data = null;
            int index = header.GetSectionIndexForRVA(rva);
            if (index != -1)
                data = section_data[index];
            return data;
        }

        public UInt32 ToSectionDataOffset(UInt32 rva)
        {
            SectionData secdat = GetSectionDataByRVA(rva);
            if (secdat == null)
            {
                return 0xFFFFFFFF;
            }
            uint offset = rva - secdat.hdr.VirtualAddress;
            return offset;
        }

        public UInt32 GetExportFunctionAddress(string function_name)
        {
            for (int i = 0; i < export_module.FunctionCount; i++)
            {
                ExportModule.Export current = export_module.exports[i];
                if (current.Name == function_name)
                {
                    return current.FuncAddress;
                }
            }
            return 0;
        }

        public UInt32 GetExportFunctionAddress(ushort function_ordinal)
        {
            for (int i = 0; i < export_module.FunctionCount; i++)
            {
                ExportModule.Export current = export_module.exports[i];
                if (current.Ordinal == function_ordinal)
                {
                    return current.FuncAddress;
                }
            }
            return 0;
        }


    }
}
