using System;
using System.Collections.Generic;
using System.Text;

namespace Noodle.Library.Models
{
    public class Section
    {
        public string Name { get; set; } = string.Empty;
        public double Entropy { get; set; } = 0.0;
        public uint VirtualAddress { get; set; }
        public uint VirtualSize { get; set; }
        public uint RawSize { get; set; }
        public uint PointerToRawData { get; set; }
        public int DataSize { get; set; }
        public bool IsPacked { get; set; }
    }
}
