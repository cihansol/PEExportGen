using System;
using System.IO;
using System.Text;
using System.Collections.Generic;

using PE;

namespace HeaderWritter
{
    public class HWriter : IDisposable
    {
        string outFilePath;
        FileStream fs;

        public HWriter(string outputFilePath)
        {
            outFilePath = outputFilePath;
            fs = new FileStream(outFilePath, FileMode.Create);
        }

        public bool WriteAllExports(PEImage image, string fallbackorigImageName)
        {
            if (!image.IsValid)
            {
               Console.WriteLine("HWriter: Invalid PE!");
               return false;
            }

            using (var sw = new StreamWriter(fs, Encoding.UTF8))
            {
                WriteHeader(sw);

                if (image.Exports == null || image.Exports.FunctionCount == 0)
                {
                    Console.WriteLine("HWriter: Encountered PE with no exports.");
                    return true;
                }

                var dllName = image.Exports.Name != string.Empty ? image.Exports.Name : fallbackorigImageName;
                var dllNameForward = Path.GetFileNameWithoutExtension(dllName) + "_orig";

                foreach (var export in image.Exports.exports)
                {
                    if (export.Name != string.Empty)
                    {
                        Console.WriteLine($"Writting {dllName} {export.Name}");
                        WriteExport(sw, dllNameForward, export.Name, export.Ordinal);
                    }
                    else
                    {
                        Console.WriteLine($"Warning!!! Unsupported {dllName} Func{export.FuncAddress:X} Ordinal:{export.Ordinal}");
                        WriteExportUnsupported(sw, dllNameForward, export.Ordinal, export.FuncAddress);
                    }

                }
            }

            return true;
        }

        public void Dispose()
        {
            outFilePath = null;
            fs.Close();
        }

        private void WriteHeader(StreamWriter sw)
        {
            sw.WriteLine($"//  {Path.GetFileName(outFilePath)}");
            sw.WriteLine("//");
            sw.WriteLine("//	Simple header to instruct the linker to forward function exports to another library.");
            sw.WriteLine("//");
            sw.WriteLine("");
        }

        private void WriteExport(StreamWriter sw, string originalImageName, string functionName, uint ordinal)
        {
            sw.WriteLine($"#pragma comment(linker,\"/export:{functionName}={originalImageName}.{functionName},@{ordinal}\")");
        }

        private void WriteExportUnsupported(StreamWriter sw, string originalImageName, uint ordinal, uint functionAddress)
        {
            sw.WriteLine($"//UNSUPPORTED FUNCTION EXPORT => #pragma comment(linker,\"/export:NONAME={originalImageName}.func_{functionAddress:X},@{ordinal}\")");
        }

    }

}
