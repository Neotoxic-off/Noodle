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

    public Task<AnalysisResult> AnalyzeAsync(string filePath, CancellationToken ct = default)
        => Task.Run(() => Analyze(filePath), ct);

    private AnalysisResult Analyze(string filePath)
    {
        var (type, magic) = FileTypeDetector.Detect(filePath);
        var (md5, sha256) = HashCalculator.Compute(filePath);

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

        var (peInfo, isPE) = _peAnalyzer.Analyze(filePath);

        var detections = ImmutableArray.CreateBuilder<Detection>();

        if (isPE && peInfo is not null)
        {
            detections.AddRange(_sectionAnalyzer.Analyze(peInfo.Sections));
            detections.AddRange(_importAnalyzer.Analyze(peInfo.Imports));

            if (peInfo.HasTls)
                detections.Add(new Detection(
                    "TLS Callbacks",
                    "Binary has TLS callbacks — code executes before the entry point, often used for anti-debug or initialization.",
                    Severity.Suspicious,
                    DetectionCategory.AntiDebug
                ));

            if (peInfo.HasOverlay)
                detections.Add(new Detection(
                    "PE Overlay",
                    "Data found after the last PE section — common in packers and self-extracting archives.",
                    Severity.Suspicious,
                    DetectionCategory.Anomaly
                ));

            if (!peInfo.HasDebugInfo)
                detections.Add(new Detection(
                    "No Debug Info",
                    "Binary has no debug directory — typical of released or obfuscated software.",
                    Severity.Safe,
                    DetectionCategory.Info
                ));
            else
                detections.Add(new Detection(
                    "Debug Info Present",
                    "Binary retains debug information — may expose source paths.",
                    Severity.Safe,
                    DetectionCategory.Info
                ));

            detections.Add(new Detection(
                $"Architecture: {peInfo.Architecture}",
                $"{peInfo.Kind} targeting {peInfo.Architecture} — {peInfo.Subsystem}.",
                Severity.Safe,
                DetectionCategory.Info
            ));

            if (peInfo.Imports.Length == 0)
                detections.Add(new Detection(
                    "No Imports",
                    "The binary has no import table — dynamically resolves all APIs at runtime (common in shellcode and advanced malware).",
                    Severity.Dangerous,
                    DetectionCategory.Anomaly
                ));
        }

        detections.AddRange(_stringExtractor.Analyze(filePath));
        detections.AddRange(_yaraScanner.Scan(filePath));

        if (!isPE)
        {
            detections.Add(new Detection(
                "Non-PE File",
                $"This is not a PE binary ({type}).",
                Severity.Safe,
                DetectionCategory.Info
            ));
        }

        return new AnalysisResult(
            Metadata:   metadata,
            PE:         peInfo,
            Detections: detections.ToImmutable(),
            IsPE:       isPE
        );
    }
}
