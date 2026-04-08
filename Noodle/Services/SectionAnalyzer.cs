using Noodle.Core.Models;

namespace Noodle.Core.Services;

public sealed class SectionAnalyzer
{
    private static readonly HashSet<string> KnownPackerSections = new(StringComparer.OrdinalIgnoreCase)
    {
        "UPX0","UPX1","UPX2",
        ".vmp0",".vmp1",
        ".themida",".winlice",
        ".MPRESS1",".MPRESS2",
        ".aspack",".asdata",
        ".nspack",".nsp0",".nsp1",".nsp2",
        ".petite",
        ".y0da",
        ".svkp",
        ".enigma1",".enigma2",
        ".ByDzik",
        ".perplex",
        ".boxed",
        ".packed",
        ".shrink",
        ".ccg",
        ".neolit",
        ".PEPACK",
        ".pebundle",
    };

    private static readonly HashSet<string> StandardSections = new(StringComparer.OrdinalIgnoreCase)
    {
        ".text",".code",
        ".data",".rdata",".rodata",
        ".bss",".sbss",
        ".rsrc",
        ".reloc",
        ".edata",".idata",
        ".pdata",".xdata",
        ".tls",".debug",
        ".sxdata",".gfids",
        ".00cfg",".retplne",
        ".textbss",
        ".CRT",".didat",
        ".msvcjmc",
    };

    public IEnumerable<Detection> Analyze(IReadOnlyList<SectionInfo> sections, uint entryPoint = 0)
    {
        if (sections.Count == 0) yield break;

        // ── Per-section checks ────────────────────────────────────────────────
        foreach (var s in sections)
        {
            // Known packer section name
            if (KnownPackerSections.Contains(s.Name))
            {
                yield return new Detection(
                    $"Packer Section: {s.Name}",
                    $"Section '{s.Name}' is a well-known packer/protector section name.",
                    Severity.Dangerous, DetectionCategory.Packing);
                continue; // skip entropy / unknown checks for this section
            }

            // Entropy checks
            if (s.IsPacked)
                yield return new Detection(
                    $"Very High Entropy: {s.Name}",
                    $"Section '{s.Name}' entropy {s.Entropy:F2}/8.0 — almost certainly encrypted or compressed (packed binary).",
                    Severity.Dangerous, DetectionCategory.Packing);
            else if (s.IsHighEntropy)
                yield return new Detection(
                    $"High Entropy: {s.Name}",
                    $"Section '{s.Name}' entropy {s.Entropy:F2}/8.0 — likely compressed or partially encrypted.",
                    Severity.Suspicious, DetectionCategory.Packing);

            // RWX — writable and executable
            if (s.IsExecutable && s.IsWritable)
                yield return new Detection(
                    $"RWX Section: {s.Name}",
                    $"Section '{s.Name}' is simultaneously writable and executable — common in shellcode loaders and memory-patching exploits.",
                    Severity.Dangerous, DetectionCategory.Anomaly);

            // Ghost section: executable but no raw data (runtime-filled)
            if (s.IsExecutable && s.RawSize == 0)
                yield return new Detection(
                    $"Ghost Executable Section: {s.Name}",
                    $"Section '{s.Name}' is marked executable but has zero raw bytes — content is entirely injected or decompressed at runtime.",
                    Severity.Dangerous, DetectionCategory.Anomaly);

            // Virtual size >> raw size (runtime decompression / packing)
            if (s.VirtualSize > 0 && s.RawSize > 0 && s.VirtualSize > s.RawSize * 10 && s.VirtualSize > 0x1000)
                yield return new Detection(
                    $"Inflated Virtual Size: {s.Name}",
                    $"Section '{s.Name}' virtual size (0x{s.VirtualSize:X}) is >{s.VirtualSize / Math.Max(1u, s.RawSize)}× its raw size (0x{s.RawSize:X}) — typical of decompression stubs that expand data at runtime.",
                    Severity.Suspicious, DetectionCategory.Packing);

            // Unknown section name
            if (!StandardSections.Contains(s.Name) && !KnownPackerSections.Contains(s.Name) && s.Name.Length > 0)
                yield return new Detection(
                    $"Non-Standard Section: {s.Name}",
                    $"Section '{s.Name}' is not a standard PE section name — may have been added by a packer or linker customisation.",
                    Severity.Suspicious, DetectionCategory.Anomaly);
        }

        // ── Aggregate / structural checks ─────────────────────────────────────

        // All sections empty (raw size)
        if (sections.All(s => s.RawSize == 0))
            yield return new Detection(
                "All Sections Empty",
                "All PE sections have zero raw size — possible memory-mapped module, reflective load, or severely corrupted PE.",
                Severity.Dangerous, DetectionCategory.Anomaly);

        // Single section — unusual for real applications
        if (sections.Count == 1)
            yield return new Detection(
                "Single-Section PE",
                "PE has only one section — extremely unusual for legitimate applications; common in shellcode loaders and minimal packers.",
                Severity.Suspicious, DetectionCategory.Anomaly);

        // Too many sections (> 12) — can indicate packer adding stubs
        if (sections.Count > 12)
            yield return new Detection(
                $"Excessive Section Count ({sections.Count})",
                $"PE has {sections.Count} sections — unusually high count; some packers add many stub sections.",
                Severity.Suspicious, DetectionCategory.Anomaly);

        // Entry point in a non-standard section
        if (entryPoint != 0)
        {
            var epSection = sections.FirstOrDefault(s =>
                entryPoint >= s.VirtualAddress &&
                entryPoint < s.VirtualAddress + Math.Max(s.VirtualSize, 1u));

            if (epSection != default &&
                !string.Equals(epSection.Name, ".text",  StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(epSection.Name, ".code",  StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(epSection.Name, "CODE",   StringComparison.OrdinalIgnoreCase))
            {
                string category = KnownPackerSections.Contains(epSection.Name) ? "packer" : "non-standard";
                yield return new Detection(
                    $"Entry Point in {epSection.Name}",
                    $"Binary entry point (0x{entryPoint:X8}) is in the {category} section '{epSection.Name}' instead of .text — hallmark of packed or tampered PE files.",
                    Severity.Dangerous, DetectionCategory.Packing);
            }
        }
    }
}
