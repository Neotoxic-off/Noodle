using System.Collections.Immutable;
using Noodle.Core.Models;
using PeNet;
using PeNet.Header.Pe;

namespace Noodle.Core.Services;

public sealed class PEAnalyzer
{
    public (PEInfo? Info, bool IsPE) Analyze(string filePath)
    {
        if (!IsPeFile(filePath)) return (null, false);

        try
        {
            var pe = new PeFile(filePath);

            var sections = pe.ImageSectionHeaders?
                .Select(s => BuildSection(filePath, s))
                .ToImmutableArray() ?? ImmutableArray<SectionInfo>.Empty;

            var imports = pe.ImportedFunctions?
                .Select(f => f.Name ?? string.Empty)
                .Where(n => n.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToImmutableArray() ?? ImmutableArray<string>.Empty;

            var exports = pe.ExportedFunctions?
                .Select(f => f.Name ?? string.Empty)
                .Where(n => n.Length > 0)
                .ToImmutableArray() ?? ImmutableArray<string>.Empty;

            var optional = pe.ImageNtHeaders?.OptionalHeader;
            var fileHeader = pe.ImageNtHeaders?.FileHeader;

            string subsystem = optional?.Subsystem switch
            {
                SubsystemType.WindowsGui    => "Windows GUI",
                SubsystemType.WindowsCui    => "Windows Console",
                SubsystemType.Native        => "Native",
                SubsystemType.EfiApplication => "EFI Application",
                SubsystemType.EfiBootServiceDriver => "EFI Boot Driver",
                SubsystemType.EfiRuntimeDriver => "EFI Runtime Driver",
                _                           => "Unknown"
            };

            bool isDll    = pe.IsDll;
            bool isDriver = subsystem == "Native";
            bool hasTls   = pe.ImageTlsDirectory is not null;
            bool hasDebug = pe.ImageDebugDirectory?.Length > 0;
            bool hasOverlay = DetectOverlay(filePath, pe);

            uint ep        = optional?.AddressOfEntryPoint ?? 0;
            uint checksum  = optional?.CheckSum ?? 0;
            long timestamp = fileHeader?.TimeDateStamp ?? 0;

            var info = new PEInfo(
                IsX64: pe.Is64Bit,
                IsDLL: isDll,
                IsDriver: isDriver,
                Subsystem: subsystem,
                EntryPoint: ep,
                TimeDateStamp: timestamp,
                Checksum: checksum,
                HasValidChecksum: checksum == 0,
                HasTls: hasTls,
                HasDebugInfo: hasDebug,
                HasOverlay: hasOverlay,
                Imports: imports,
                Exports: exports,
                Sections: sections
            );

            return (info, true);
        }
        catch
        {
            return (null, false);
        }
    }

    private static bool IsPeFile(string path)
    {
        try
        {
            if (!File.Exists(path)) return false;
            using var fs = File.OpenRead(path);
            if (fs.Length < 64) return false;
            using var reader = new BinaryReader(fs);
            if (reader.ReadUInt16() != 0x5A4D) return false;
            fs.Seek(0x3C, SeekOrigin.Begin);
            int peOffset = reader.ReadInt32();
            if (peOffset <= 0 || peOffset > fs.Length - 4) return false;
            fs.Seek(peOffset, SeekOrigin.Begin);
            return reader.ReadUInt32() == 0x00004550;
        }
        catch { return false; }
    }

    private static SectionInfo BuildSection(string filePath, ImageSectionHeader s)
    {
        var name = new string(s.Name).TrimEnd('\0').Trim();
        double entropy = 0;
        try
        {
            if (s.SizeOfRawData > 0)
            {
                using var fs = File.OpenRead(filePath);
                fs.Seek(s.PointerToRawData, SeekOrigin.Begin);
                var buf = new byte[Math.Min(s.SizeOfRawData, 65536u)];
                int read = fs.Read(buf);
                entropy = EntropyCalculator.Calculate(buf.AsSpan(0, read));
            }
        }
        catch { }

        bool isExec  = s.Characteristics.HasFlag(ScnCharacteristicsType.MemExecute);
        bool isWrite = s.Characteristics.HasFlag(ScnCharacteristicsType.MemWrite);

        return new SectionInfo(
            Name: name,
            Entropy: entropy,
            VirtualAddress: s.VirtualAddress,
            VirtualSize: s.VirtualSize,
            RawSize: s.SizeOfRawData,
            PointerToRawData: s.PointerToRawData,
            IsExecutable: isExec,
            IsWritable: isWrite
        );
    }

    private static bool DetectOverlay(string filePath, PeFile pe)
    {
        try
        {
            var lastSection = pe.ImageSectionHeaders?
                .OrderByDescending(s => s.PointerToRawData)
                .FirstOrDefault();
            if (lastSection is null) return false;
            long end = (long)lastSection.PointerToRawData + lastSection.SizeOfRawData;
            return new FileInfo(filePath).Length > end + 1024;
        }
        catch { return false; }
    }
}
