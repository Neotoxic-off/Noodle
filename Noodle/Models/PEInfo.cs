using System.Collections.Immutable;

namespace Noodle.Core.Models;

public sealed record PEInfo(
    bool IsX64,
    bool IsDLL,
    bool IsDriver,
    string Subsystem,
    uint EntryPoint,
    long TimeDateStamp,
    uint Checksum,
    bool HasValidChecksum,
    bool HasTls,
    bool HasDebugInfo,
    bool HasOverlay,
    ImmutableArray<string> Imports,
    ImmutableArray<string> Exports,
    ImmutableArray<SectionInfo> Sections
)
{
    public string Architecture => IsX64 ? "x64" : "x86";
    public string Kind         => IsDLL ? "DLL" : IsDriver ? "Driver" : "Executable";
}
