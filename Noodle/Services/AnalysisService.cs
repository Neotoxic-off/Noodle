using System.Collections.Immutable;
using Noodle.Core.Models;

namespace Noodle.Core.Services;

public sealed class AnalysisService : IAnalysisService
{
    private readonly PEAnalyzer      _peAnalyzer      = new();
    private readonly SectionAnalyzer _sectionAnalyzer = new();
    private readonly ImportAnalyzer  _importAnalyzer  = new();
    private readonly StringExtractor _stringExtractor = new();
    private readonly YaraScanner     _yaraScanner     = new();
    private readonly AsmAnalyzer     _asmAnalyzer     = new();

    public Task<AnalysisResult> AnalyzeAsync(
        string filePath,
        IProgress<string>? progress = null,
        CancellationToken ct = default)
        => Task.Run(() => Analyze(filePath, progress), ct);

    private AnalysisResult Analyze(string filePath, IProgress<string>? p)
    {
        void Step(string msg) => p?.Report(msg);

        // ── File metadata ─────────────────────────────────────────────────────
        Step("[INIT] Computing hashes…");
        var (md5, sha256) = HashCalculator.Compute(filePath);

        Step("[INIT] Detecting file type…");
        var (type, magic) = FileTypeDetector.Detect(filePath);

        long size = 0;
        try { size = new FileInfo(filePath).Length; } catch { }

        var metadata = new FileMetadata(
            FilePath:   filePath,
            FileName:   Path.GetFileName(filePath),
            FileSize:   size,
            MD5:        md5,
            SHA256:     sha256,
            FileType:   type,
            MagicBytes: magic
        );

        // ── PE parsing ────────────────────────────────────────────────────────
        Step("[PE] Parsing binary structure…");
        var (peInfo, isPE) = _peAnalyzer.Analyze(filePath);

        var detections = ImmutableArray.CreateBuilder<Detection>();

        if (isPE && peInfo is not null)
        {
            // Sections
            Step($"[PE] Analyzing {peInfo.Sections.Length} section(s)…");
            detections.AddRange(_sectionAnalyzer.Analyze(peInfo.Sections, peInfo.EntryPoint));

            // Imports
            Step($"[PE] Scanning {peInfo.Imports.Length} import(s)…");
            detections.AddRange(_importAnalyzer.Analyze(peInfo.Imports));

            // ASM
            Step("[ASM] Disassembling entry point region…");
            detections.AddRange(_asmAnalyzer.Analyze(filePath, peInfo));

            // TLS callbacks
            if (peInfo.HasTls)
                detections.Add(new Detection(
                    "TLS Callbacks",
                    "Binary has Thread-Local Storage callbacks — code executes before the declared entry point, often used for anti-debug or runtime initialisation.",
                    Severity.Suspicious, DetectionCategory.AntiDebug));

            // PE overlay
            if (peInfo.HasOverlay)
                detections.Add(new Detection(
                    "PE Overlay Data",
                    "Data appended after the last PE section — common in packers, self-extracting archives, and payloads appended by builders.",
                    Severity.Suspicious, DetectionCategory.Anomaly));

            // Debug info
            if (!peInfo.HasDebugInfo)
                detections.Add(new Detection(
                    "No Debug Info",
                    "Binary has no debug directory — typical of release builds, stripped or obfuscated executables.",
                    Severity.Safe, DetectionCategory.Info));
            else
                detections.Add(new Detection(
                    "Debug Info Present",
                    "Binary retains a debug directory — may expose PDB paths or source file names.",
                    Severity.Safe, DetectionCategory.Info));

            // Architecture info
            detections.Add(new Detection(
                $"Architecture: {peInfo.Architecture}",
                $"{peInfo.Kind} targeting {peInfo.Architecture} — {peInfo.Subsystem}.",
                Severity.Safe, DetectionCategory.Info));

            // Timestamp anomalies
            if (peInfo.TimeDateStamp > 0)
            {
                var compiled = DateTimeOffset.FromUnixTimeSeconds(peInfo.TimeDateStamp).UtcDateTime;
                if (compiled > DateTime.UtcNow.AddDays(7))
                    detections.Add(new Detection(
                        "Future Compile Timestamp",
                        $"PE timestamp is {compiled:yyyy-MM-dd} — a future date may indicate deliberate manipulation to confuse forensic tools.",
                        Severity.Suspicious, DetectionCategory.Anomaly));
                else if (compiled.Year < 2000)
                    detections.Add(new Detection(
                        "Invalid Compile Timestamp",
                        $"PE timestamp is {compiled:yyyy-MM-dd} — a date before 2000 is almost certainly spoofed.",
                        Severity.Suspicious, DetectionCategory.Anomaly));
            }

            // Checksum
            if (peInfo.Checksum != 0 && !peInfo.HasValidChecksum)
                detections.Add(new Detection(
                    "Invalid PE Checksum",
                    "The PE optional header checksum does not match the computed value — binary may have been patched or tampered with.",
                    Severity.Suspicious, DetectionCategory.Anomaly));

            // Import table presence
            if (peInfo.Imports.Length == 0)
                detections.Add(new Detection(
                    "No Import Table",
                    "Binary has no import table — all APIs are resolved dynamically at runtime (common in shellcode and advanced malware).",
                    Severity.Dangerous, DetectionCategory.Anomaly));
            else
                detections.Add(new Detection(
                    $"Import Table ({peInfo.Imports.Length} functions)",
                    $"Binary imports {peInfo.Imports.Length} named function(s) across its import table.",
                    Severity.Safe, DetectionCategory.Info));
        }

        // ── String / IOC extraction ───────────────────────────────────────────
        Step("[STR] Extracting embedded strings and IOCs…");
        detections.AddRange(_stringExtractor.Analyze(filePath));

        // ── Signature / YARA scanning ─────────────────────────────────────────
        Step("[SIG] Running byte signature rules…");
        int yaraFileCount = _yaraScanner.RuleFileCount;
        if (yaraFileCount > 0)
            Step($"[YARA] Applying {yaraFileCount} custom rule file(s)…");
        detections.AddRange(_yaraScanner.Scan(filePath));

        if (!isPE)
            detections.Add(new Detection(
                "Non-PE File",
                $"This file is not a PE binary — detected as {type}.",
                Severity.Safe, DetectionCategory.Info));

        var result = new AnalysisResult(
            Metadata:   metadata,
            PE:         peInfo,
            Detections: detections.ToImmutable(),
            IsPE:       isPE);

        Step($"[DONE] Scan complete — {result.Detections.Length} finding(s), threat score {result.ThreatScore}/100.");
        return result;
    }
}
