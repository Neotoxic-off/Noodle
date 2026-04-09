using System.Collections.Immutable;
using System.Text;
using Noodle.Core.Models;
using PeNet;
using PeNet.Header.Pe;

namespace Noodle.Core.Services;

public sealed class PEAnalyzer
{
    public (PEInfo? Info, bool IsPE) Analyze(string filePath)
    {
        PeFile                          pe           = null!;
        ImmutableArray<SectionInfo>     sections     = ImmutableArray<SectionInfo>.Empty;
        ImmutableArray<ImportEntry>     imports      = ImmutableArray<ImportEntry>.Empty;
        ImmutableArray<string>          exports      = ImmutableArray<string>.Empty;
        ImageOptionalHeader?            optional     = null;
        ImageFileHeader?                fileHeader   = null;
        string                          subsystem    = "";
        bool                            isDll        = false;
        bool                            isDriver     = false;
        bool                            hasTls       = false;
        bool                            hasDebug     = false;
        bool                            hasOverlay   = false;
        bool                            isDotNet     = false;
        uint                            ep           = 0;
        uint                            checksum     = 0;
        long                            timestamp    = 0L;
        string                          linkerVer    = "";
        string                          clrVer       = "";
        string                          pdbPath      = "";
        int                             resourceCount = 0;
        PEInfo                          info         = default!;

        if (!IsPeFile(filePath)) return (null, false);

        pe = new PeFile(filePath);

        sections = pe.ImageSectionHeaders?
            .Select(s => BuildSection(filePath, s))
            .ToImmutableArray() ?? ImmutableArray<SectionInfo>.Empty;

        imports = pe.ImportedFunctions?
            .Where(f => f.Name?.Length > 0)
            .Select(f => new ImportEntry(f.DLL ?? "unknown", f.Name!))
            .ToImmutableArray() ?? ImmutableArray<ImportEntry>.Empty;

        exports = pe.ExportedFunctions?
            .Select(f => f.Name ?? string.Empty)
            .Where(n => n.Length > 0)
            .ToImmutableArray() ?? ImmutableArray<string>.Empty;

        optional   = pe.ImageNtHeaders?.OptionalHeader;
        fileHeader = pe.ImageNtHeaders?.FileHeader;

        subsystem = optional?.Subsystem switch
        {
            SubsystemType.WindowsGui          => "Windows GUI",
            SubsystemType.WindowsCui          => "Windows Console",
            SubsystemType.Native              => "Native",
            SubsystemType.EfiApplication      => "EFI Application",
            SubsystemType.EfiBootServiceDriver => "EFI Boot Driver",
            SubsystemType.EfiRuntimeDriver    => "EFI Runtime Driver",
            _                                 => "Unknown"
        };

        isDll      = pe.IsDll;
        isDriver   = subsystem == "Native";
        hasTls     = pe.ImageTlsDirectory is not null;
        hasDebug   = pe.ImageDebugDirectory?.Length > 0;
        hasOverlay = DetectOverlay(filePath, pe);
        isDotNet   = pe.IsDotNet;

        ep        = optional?.AddressOfEntryPoint ?? 0;
        checksum  = optional?.CheckSum ?? 0;
        timestamp = fileHeader?.TimeDateStamp ?? 0;

        linkerVer = optional is not null
            ? $"{optional.MajorLinkerVersion}.{optional.MinorLinkerVersion}"
            : "";

        clrVer    = ExtractClrVersion(filePath, pe, isDotNet);
        pdbPath   = ExtractPdbPath(filePath, pe);

        resourceCount = pe.ImageResourceDirectory?.DirectoryEntries?.Count ?? 0;

        info = new PEInfo(
            IsX64:           pe.Is64Bit,
            IsDLL:           isDll,
            IsDriver:        isDriver,
            IsDotNet:        isDotNet,
            Subsystem:       subsystem,
            EntryPoint:      ep,
            TimeDateStamp:   timestamp,
            Checksum:        checksum,
            HasValidChecksum: checksum == 0,
            HasTls:          hasTls,
            HasDebugInfo:    hasDebug,
            HasOverlay:      hasOverlay,
            LinkerVersion:   linkerVer,
            PdbPath:         pdbPath,
            ClrVersion:      clrVer,
            ResourceCount:   resourceCount,
            Imports:         imports,
            Exports:         exports,
            Sections:        sections
        );

        return (info, true);
    }

    private static string ExtractClrVersion(string filePath, PeFile pe, bool isDotNet)
    {
        ImageDataDirectory?  comDir     = null;
        ImageSectionHeader?  section    = null;
        uint                 fileOffset = 0;
        ushort               major      = 0;
        ushort               minor      = 0;

        if (!isDotNet) return "";

        comDir = pe.ImageNtHeaders?.OptionalHeader?.DataDirectory?[14];
        if (comDir is null || comDir.VirtualAddress == 0) return "";

        section = pe.ImageSectionHeaders?
            .FirstOrDefault(s => comDir.VirtualAddress >= s.VirtualAddress
                              && comDir.VirtualAddress <  s.VirtualAddress + s.VirtualSize);
        if (section is null) return "";

        fileOffset = section.PointerToRawData + (comDir.VirtualAddress - section.VirtualAddress);

        using FileStream   fs     = File.OpenRead(filePath);
        using BinaryReader reader = new BinaryReader(fs);

        fs.Seek(fileOffset, SeekOrigin.Begin);
        reader.ReadUInt32();
        major = reader.ReadUInt16();
        minor = reader.ReadUInt16();

        return $"{major}.{minor}";
    }

    private static string ExtractPdbPath(string filePath, PeFile pe)
    {
        ImageDebugDirectory[]? debugDirs = null;
        byte[]                 buf       = [];
        int                    read      = 0;

        debugDirs = pe.ImageDebugDirectory;
        if (debugDirs is null) return "";

        foreach (ImageDebugDirectory dir in debugDirs)
        {
            if (dir.Type != 2 || dir.SizeOfData < 24) continue;

            using FileStream fs = File.OpenRead(filePath);
            fs.Seek(dir.PointerToRawData, SeekOrigin.Begin);

            buf  = new byte[dir.SizeOfData];
            read = fs.Read(buf);

            if (read < 24) continue;

            if (buf[0] == 'R' && buf[1] == 'S' && buf[2] == 'D' && buf[3] == 'S')
            {
                return NullTermStr(buf, 24);
            }

            if (buf[0] == 'N' && buf[1] == 'B' && buf[2] == '1' && buf[3] == '0')
            {
                return NullTermStr(buf, 16);
            }
        }

        return "";
    }

    private static string NullTermStr(byte[] buf, int start)
    {
        int end = start;

        while (end < buf.Length && buf[end] != 0) end = end + 1;

        return Encoding.UTF8.GetString(buf, start, end - start);
    }

    private static bool IsPeFile(string path)
    {
        int peOffset = 0;

        if (!File.Exists(path)) return false;

        using FileStream   fs     = File.OpenRead(path);
        using BinaryReader reader = new BinaryReader(fs);

        if (fs.Length < 64) return false;
        if (reader.ReadUInt16() != 0x5A4D) return false;

        fs.Seek(0x3C, SeekOrigin.Begin);
        peOffset = reader.ReadInt32();

        if (peOffset <= 0 || peOffset > fs.Length - 4) return false;

        fs.Seek(peOffset, SeekOrigin.Begin);

        return reader.ReadUInt32() == 0x00004550;
    }

    private static SectionInfo BuildSection(string filePath, ImageSectionHeader s)
    {
        string   name    = new string(s.Name).TrimEnd('\0').Trim();
        double   entropy = 0;
        bool     isExec  = false;
        bool     isWrite = false;

        if (s.SizeOfRawData > 0)
        {
            using FileStream fs  = File.OpenRead(filePath);
            byte[]           buf = new byte[Math.Min(s.SizeOfRawData, 65536u)];
            int              read = 0;

            fs.Seek(s.PointerToRawData, SeekOrigin.Begin);
            read    = fs.Read(buf);
            entropy = EntropyCalculator.Calculate(buf.AsSpan(0, read));
        }

        isExec  = s.Characteristics.HasFlag(ScnCharacteristicsType.MemExecute);
        isWrite = s.Characteristics.HasFlag(ScnCharacteristicsType.MemWrite);

        return new SectionInfo(
            Name:             name,
            Entropy:          entropy,
            VirtualAddress:   s.VirtualAddress,
            VirtualSize:      s.VirtualSize,
            RawSize:          s.SizeOfRawData,
            PointerToRawData: s.PointerToRawData,
            IsExecutable:     isExec,
            IsWritable:       isWrite
        );
    }

    private static bool DetectOverlay(string filePath, PeFile pe)
    {
        ImageSectionHeader? lastSection = null;
        long                end         = 0L;

        lastSection = pe.ImageSectionHeaders?
            .OrderByDescending(s => s.PointerToRawData)
            .FirstOrDefault();

        if (lastSection is null) return false;

        end = (long)lastSection.PointerToRawData + lastSection.SizeOfRawData;

        return new FileInfo(filePath).Length > end + 1024;
    }
}
