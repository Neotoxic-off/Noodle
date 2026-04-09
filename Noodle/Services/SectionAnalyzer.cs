using Noodle.Core.Models;

namespace Noodle.Core.Services;

public sealed class SectionAnalyzer
{
    private static readonly HashSet<string> CodeSections = new(StringComparer.OrdinalIgnoreCase)
    {
        ".text", ".code", "CODE"
    };

    public IEnumerable<Detection> Analyze(IReadOnlyList<SectionInfo> sections, uint entryPoint = 0)
    {
        if (sections.Count == 0) yield break;

        foreach (SectionInfo s in sections)
        {
            if (s.IsPacked)
                yield return new Detection(
                    $"Very High Entropy: {s.Name}",
                    $"Section '{s.Name}' entropy {s.Entropy:F2}/8.0 — almost certainly encrypted or compressed.",
                    Severity.Dangerous, DetectionCategory.Packing);
            else if (s.IsHighEntropy)
                yield return new Detection(
                    $"High Entropy: {s.Name}",
                    $"Section '{s.Name}' entropy {s.Entropy:F2}/8.0 — likely compressed or partially encrypted.",
                    Severity.Suspicious, DetectionCategory.Packing);

            if (s.IsExecutable && s.IsWritable)
                yield return new Detection(
                    $"RWX Section: {s.Name}",
                    $"Section '{s.Name}' is simultaneously writable and executable — common in shellcode loaders.",
                    Severity.Dangerous, DetectionCategory.Anomaly);

            if (s.IsExecutable && s.RawSize == 0)
                yield return new Detection(
                    $"Ghost Executable Section: {s.Name}",
                    $"Section '{s.Name}' is marked executable but has zero raw bytes — content injected or decompressed at runtime.",
                    Severity.Dangerous, DetectionCategory.Anomaly);

            if (s.VirtualSize > 0 && s.RawSize > 0 && s.VirtualSize > s.RawSize * 10 && s.VirtualSize > 0x1000)
                yield return new Detection(
                    $"Inflated Virtual Size: {s.Name}",
                    $"Section '{s.Name}' virtual size (0x{s.VirtualSize:X}) is >{s.VirtualSize / Math.Max(1u, s.RawSize)}× its raw size — typical of runtime decompression stubs.",
                    Severity.Suspicious, DetectionCategory.Packing);
        }

        if (sections.All(s => s.RawSize == 0))
            yield return new Detection(
                "All Sections Empty",
                "All PE sections have zero raw size — memory-mapped module, reflective load, or corrupted PE.",
                Severity.Dangerous, DetectionCategory.Anomaly);

        if (sections.Count == 1)
            yield return new Detection(
                "Single-Section PE",
                "PE has only one section — extremely unusual for legitimate applications; common in shellcode loaders.",
                Severity.Suspicious, DetectionCategory.Anomaly);

        if (sections.Count > 12)
            yield return new Detection(
                $"Excessive Section Count ({sections.Count})",
                $"PE has {sections.Count} sections — unusually high count, some packers add many stub sections.",
                Severity.Suspicious, DetectionCategory.Anomaly);

        if (entryPoint != 0)
        {
            SectionInfo? epSection = sections.FirstOrDefault(s =>
                entryPoint >= s.VirtualAddress &&
                entryPoint < s.VirtualAddress + Math.Max(s.VirtualSize, 1u));

            if (epSection is not null && !CodeSections.Contains(epSection.Name))
                yield return new Detection(
                    $"Entry Point in {epSection.Name}",
                    $"Binary entry point (0x{entryPoint:X8}) is in section '{epSection.Name}' instead of .text — hallmark of packed or tampered PE.",
                    Severity.Dangerous, DetectionCategory.Packing);
        }
    }
}
