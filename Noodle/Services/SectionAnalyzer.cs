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
    };

    public IEnumerable<Detection> Analyze(IReadOnlyList<SectionInfo> sections)
    {
        foreach (var s in sections)
        {
            if (KnownPackerSections.Contains(s.Name))
            {
                yield return new Detection(
                    $"Packer Section: {s.Name}",
                    $"Section '{s.Name}' is a known packer/protector section name.",
                    Severity.Dangerous,
                    DetectionCategory.Packing
                );
                continue;
            }

            if (s.IsPacked)
            {
                yield return new Detection(
                    $"High Entropy: {s.Name}",
                    $"Section '{s.Name}' has very high entropy ({s.Entropy:F2}/8.0), strongly suggesting encryption or compression.",
                    Severity.Dangerous,
                    DetectionCategory.Packing
                );
            }
            else if (s.IsHighEntropy)
            {
                yield return new Detection(
                    $"Elevated Entropy: {s.Name}",
                    $"Section '{s.Name}' has elevated entropy ({s.Entropy:F2}/8.0), possibly compressed or partially encrypted.",
                    Severity.Suspicious,
                    DetectionCategory.Packing
                );
            }

            if (s.IsExecutable && s.IsWritable)
            {
                yield return new Detection(
                    $"RWX Section: {s.Name}",
                    $"Section '{s.Name}' is both writable and executable — common in shellcode loaders and exploits.",
                    Severity.Dangerous,
                    DetectionCategory.Anomaly
                );
            }

            if (!StandardSections.Contains(s.Name) && !KnownPackerSections.Contains(s.Name) && s.Name.Length > 0)
            {
                yield return new Detection(
                    $"Unknown Section: {s.Name}",
                    $"Section '{s.Name}' is not a standard PE section name.",
                    Severity.Suspicious,
                    DetectionCategory.Anomaly
                );
            }
        }

        if (sections.Count > 0 && sections.All(s => s.RawSize == 0))
        {
            yield return new Detection(
                "All Sections Empty",
                "All PE sections have zero raw size — possible memory-loaded shellcode or severely corrupted PE.",
                Severity.Dangerous,
                DetectionCategory.Anomaly
            );
        }
    }
}
