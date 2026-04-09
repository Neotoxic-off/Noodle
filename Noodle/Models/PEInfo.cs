using System.Collections.Immutable;

namespace Noodle.Core.Models;

public sealed record PEInfo(
    bool IsX64,
    bool IsDLL,
    bool IsDriver,
    bool IsDotNet,
    string Subsystem,
    uint EntryPoint,
    long TimeDateStamp,
    uint Checksum,
    bool HasValidChecksum,
    bool HasTls,
    bool HasDebugInfo,
    bool HasOverlay,
    string LinkerVersion,
    string PdbPath,
    string ClrVersion,
    int ResourceCount,
    ImmutableArray<ImportEntry> Imports,
    ImmutableArray<string> Exports,
    ImmutableArray<SectionInfo> Sections
)
{
    public string Architecture => IsX64 ? "x64" : "x86";
    public string Kind         => IsDLL ? "DLL" : IsDriver ? "Driver" : "Executable";
}
