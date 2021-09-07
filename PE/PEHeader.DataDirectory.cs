using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.IO;

namespace PE
{
    public partial class PEHeader
    {

        //ExportTable;
        //ImportTable;
        //ResourceTable;
        //ExceptionTable;
        //CertificateTable;
        //BaseRelocationTable;
        //Debug;
        //Architecture;
        //GlobalPtr;
        //TLSTable;
        //LoadConfigTable;
        //BoundImport;
        //IAT;
        //DelayImportDescriptor;
        //CLRRuntimeHeader;
        //Reserved;


        private bool ReadSection_ExportTable_br(BinaryReader reader)
        {
            UInt32 offset;

            //Parse Export Directory if it exists
            if (this.Is32BitHeader)
            {
                if (optionalHeader32.ExportTable.VirtualAddress == 0 || optionalHeader32.ExportTable.Size == 0 || optionalHeader32.ExportTable.Size < IMAGE_EXPORT_DIRECTORY_SIZE)
                    return false;
                offset = GetFileOffsetFromRVA(optionalHeader32.ExportTable.VirtualAddress);
            }
            else
            {
                if (optionalHeader64.ExportTable.VirtualAddress == 0 || optionalHeader64.ExportTable.Size == 0 || optionalHeader64.ExportTable.Size < IMAGE_EXPORT_DIRECTORY_SIZE)
                    return false;
                offset = GetFileOffsetFromRVA(optionalHeader64.ExportTable.VirtualAddress);
            }

            if (offset == 0xFFFFFFFF)
                return false;

            reader.BaseStream.Seek(offset, SeekOrigin.Begin);
            imageExportDirectory = FromBinaryReader<IMAGE_EXPORT_DIRECTORY>(reader);

            return true;
        }

    }
}
