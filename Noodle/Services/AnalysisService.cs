using System.Collections.Immutable;
using Noodle.Core.Models;

namespace Noodle.Core.Services;

public sealed class AnalysisService : IAnalysisService
{
    private readonly PEAnalyzer      _peAnalyzer      = new();
    private readonly SectionAnalyzer _sectionAnalyzer = new();
    private readonly StringExtractor _stringExtractor = new();
    private readonly YaraScanner     _yaraScanner     = new();
    private readonly AsmAnalyzer     _asmAnalyzer     = new();

    public Task<AnalysisResult> AnalyzeAsync(
        string filePath,
        IProgress<ScanProgress>? progress = null,
        CancellationToken ct = default)
        => Task.Run(() => Analyze(filePath, progress), ct);

    private AnalysisResult Analyze(string filePath, IProgress<ScanProgress>? p)
    {
        const int total = 10;

        int                              step         = 0;
        string                           md5          = "";
        string                           sha256       = "";
        string                           type         = "";
        string                           magic        = "";
        long                             size         = 0L;
        FileMetadata                     metadata     = default!;
        PEInfo?                          peInfo       = null;
        bool                             isPE         = false;
        ImmutableArray<Detection>.Builder detections  = ImmutableArray.CreateBuilder<Detection>();
        int                              yaraFileCount = 0;
        ImmutableArray<YaraRuleResult>   yaraResults  = ImmutableArray<YaraRuleResult>.Empty;
        CompilerInfo?                    compilerInfo = null;
        DateTime                         compiled     = default;

        void Step(string msg) => p?.Report(new ScanProgress(msg, ++step, total));

        Step("[INIT] Computing hashes…");
        (md5, sha256) = HashCalculator.Compute(filePath);

        Step("[INIT] Detecting file type…");
        (type, magic) = FileTypeDetector.Detect(filePath);

        size     = File.Exists(filePath) ? new FileInfo(filePath).Length : 0L;
        metadata = new FileMetadata(
            FilePath:   filePath,
            FileName:   Path.GetFileName(filePath),
            FileSize:   size,
            MD5:        md5,
            SHA256:     sha256,
            FileType:   type,
            MagicBytes: magic
        );

        Step("[PE] Parsing binary structure…");
        (peInfo, isPE) = _peAnalyzer.Analyze(filePath);

        if (isPE && peInfo is not null)
        {
            Step($"[PE] Analyzing {peInfo.Sections.Length} section(s)…");
            detections.AddRange(_sectionAnalyzer.Analyze(peInfo.Sections, peInfo.EntryPoint));

            Step("[ASM] Disassembling entry point region…");
            detections.AddRange(_asmAnalyzer.Analyze(filePath, peInfo));

            Step("[PE] Checking TLS / overlay / debug / timestamps…");

            if (peInfo.HasTls)
                detections.Add(new Detection(
                    "TLS Callbacks",
                    "Binary has Thread-Local Storage callbacks — code executes before the declared entry point, often used for anti-debug or runtime initialisation.",
                    Severity.Suspicious, DetectionCategory.AntiDebug));

            if (peInfo.HasOverlay)
                detections.Add(new Detection(
                    "PE Overlay Data",
                    "Data appended after the last PE section — common in packers, self-extracting archives, and payloads appended by builders.",
                    Severity.Suspicious, DetectionCategory.Anomaly));

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

            detections.Add(new Detection(
                $"Architecture: {peInfo.Architecture}",
                $"{peInfo.Kind} targeting {peInfo.Architecture} — {peInfo.Subsystem}.",
                Severity.Safe, DetectionCategory.Info));

            if (peInfo.TimeDateStamp > 0)
            {
                compiled = DateTimeOffset.FromUnixTimeSeconds(peInfo.TimeDateStamp).UtcDateTime;

                if (compiled > DateTime.UtcNow.AddDays(7))
                    detections.Add(new Detection(
                        "Future Compile Timestamp",
                        $"PE timestamp is {compiled:yyyy-MM-dd} — a future date may indicate deliberate manipulation.",
                        Severity.Suspicious, DetectionCategory.Anomaly));
                else if (compiled.Year < 2000)
                    detections.Add(new Detection(
                        "Invalid Compile Timestamp",
                        $"PE timestamp is {compiled:yyyy-MM-dd} — a date before 2000 is almost certainly spoofed.",
                        Severity.Suspicious, DetectionCategory.Anomaly));
            }

            if (peInfo.Checksum != 0 && !peInfo.HasValidChecksum)
                detections.Add(new Detection(
                    "Invalid PE Checksum",
                    "The PE optional header checksum does not match the computed value — binary may have been patched or tampered with.",
                    Severity.Suspicious, DetectionCategory.Anomaly));

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
        else
        {
            step += 3;
            p?.Report(new ScanProgress("[PE] Not a PE binary, skipping PE analysis.", step, total));
        }

        Step("[STR] Extracting embedded strings and IOCs…");
        detections.AddRange(_stringExtractor.Analyze(filePath));

        Step("[SIG] Running byte signature rules…");
        detections.AddRange(_yaraScanner.Scan(filePath));

        yaraFileCount = _yaraScanner.RuleFileCount;

        Step(yaraFileCount > 0
            ? $"[YARA] Applying {yaraFileCount} custom rule file(s)…"
            : "[YARA] No custom rule files found.");

        yaraResults = _yaraScanner.ScanCustomRules(
            filePath,
            (ruleName, subStep, subTotal) =>
                p?.Report(new ScanProgress($"[YARA] {ruleName}", step, total, subStep, subTotal))
        ).ToImmutableArray();

        foreach (YaraRuleResult yr in yaraResults.Where(r => r.Matched))
            detections.Add(new Detection($"YARA: {yr.Name}", yr.Description, yr.Severity, DetectionCategory.Yara));

        if (!isPE)
            detections.Add(new Detection(
                "Non-PE File",
                $"This file is not a PE binary — detected as {type}.",
                Severity.Safe, DetectionCategory.Info));

        Step("[COMP] Detecting compiler and language…");
        compilerInfo = isPE && peInfo is not null
            ? CompilerDetector.Detect(peInfo)
            : null;

        p?.Report(new ScanProgress(
            $"[DONE] Scan complete — {detections.Count} finding(s).",
            total, total));

        return new AnalysisResult(
            Metadata:    metadata,
            PE:          peInfo,
            Compiler:    compilerInfo,
            Detections:  detections.ToImmutable(),
            YaraResults: yaraResults,
            IsPE:        isPE);
    }
}
