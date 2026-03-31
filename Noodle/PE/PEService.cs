using Noodle.Library.Models;
using PeNet;
using PeNet.Header.Pe;
using System;
using System.Collections.Generic;
using System.Text;

namespace Noodle.Library.PE
{
    public class PEService
    {
        private PeFile? peFile { get; set; }
        private string? binaryPath { get; set; }

        public void Update(string path)
        {
            binaryPath = path;
        }

        public void LoadPE()
        {
            if (binaryPath is not null)
            {
                peFile = new PeFile(binaryPath);
            }
        }

        public bool IsPeFile(string path)
        {
            bool isPe = false;
            int peOffset = 0;

            if (File.Exists(path))
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read))
                using (BinaryReader reader = new BinaryReader(fs))
                {
                    if (fs.Length >= 64 && reader.ReadUInt16() == 0x5A4D)
                    {
                        fs.Seek(0x3C, SeekOrigin.Begin);
                        peOffset = reader.ReadInt32();

                        if (peOffset > 0 && peOffset <= fs.Length - 4)
                        {
                            fs.Seek(peOffset, SeekOrigin.Begin);
                            if (reader.ReadUInt32() == 0x00004550)
                            {
                                isPe = true;
                            }
                        }
                    }
                }
            }

            return isPe;
        }

        public List<Section> GetSections()
        {
            List<Section> sections = new List<Section>();

            if (peFile.ImageSectionHeaders is not null)
            {
                foreach (ImageSectionHeader section in peFile.ImageSectionHeaders)
                {
                    sections.Add(new Section()
                    {
                        Name = section.Name,
                        VirtualAddress = section.VirtualAddress,
                        VirtualSize = section.VirtualSize,
                        RawSize = section.SizeOfRawData,
                        PointerToRawData = section.PointerToRawData
                    });
                }
            }

            return sections;
        }
    }
}
