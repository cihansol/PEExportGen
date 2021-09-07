using System;
using System.IO;
using System.Reflection;

using PE;
using HeaderWritter;

namespace PEExportGen
{
    class Program
    {

        static void Main(string[] args)
        {
            Console.WriteLine("PEExportGen");
            Console.WriteLine("Author: Cihan");
            Console.WriteLine(string.Empty);

            if (args.Length < 1)
            {
                Console.WriteLine("Usage: PEExportGen path/to/library.dll");
                Console.WriteLine(" ");
                Console.WriteLine("Example: PEExportGen C:/Windows/System32/IPHLPAPI.DLL");
                Console.WriteLine("Press any key to exit");
                Console.ReadKey();
                return;
            }

            string workingDirectory = GetApplicationDirectory();
            string inputFile = args[0];

            if (!File.Exists(inputFile))
            {
                //Check the working directory
                string newWorkingDirPath = Path.Combine(workingDirectory, inputFile);
                if (File.Exists(newWorkingDirPath))
                    inputFile = newWorkingDirPath;
                else
                {
                    Console.WriteLine($"Error Input file {inputFile} doesn't seem to exist!");
                    return;
                }
            }

            //Load the PE Image
            PEImage img = new PEImage();
            if (!img.Load(inputFile))
            {
                Console.WriteLine("Error loading PE Image!");
                return;
            }

            //Write out all the exports to a header file
            string outHeaderFilePath = Path.Combine(Path.GetDirectoryName(inputFile), "exports.h");
            using (HWriter hw = new HWriter(outHeaderFilePath))
            {
                hw.WriteAllExports(img, Path.GetFileName(inputFile));
            }

            Console.WriteLine("Done.");
            return;
        }

        public static string GetApplicationDirectory()
        {
            var dir = AppDomain.CurrentDomain.BaseDirectory;
            if (Directory.Exists(dir))
                return dir;
            else
                return Path.GetDirectoryName(Assembly.GetEntryAssembly().Location);
        }


    }
}
