using Noodle.Core.Models;

namespace Noodle.Core.Services;

// YaraSharp targets .NET Framework only and cannot be used on modern .NET.
// YARA scanning is disabled until a compatible library is available.
public sealed class YaraScanner
{
    public IEnumerable<Detection> Scan(string filePath) => [];
}
