using System.Collections.Immutable;

namespace Noodle.Core.Models;

public sealed record AnalysisResult(
    FileMetadata Metadata,
    PEInfo? PE,
    ImmutableArray<Detection> Detections,
    bool IsPE
)
{
    public Severity OverallSeverity => Detections.IsEmpty
        ? Severity.Safe
        : Detections.Max(d => d.Severity);

    public int ThreatScore
    {
        get
        {
            int score = 0;
            foreach (var d in Detections)
                score += d.Severity switch
                {
                    Severity.Dangerous  => 20,
                    Severity.Suspicious => 5,
                    _                   => 0
                };
            return Math.Min(100, score);
        }
    }

    public string Verdict => ThreatScore switch
    {
        >= 80 => "Likely Malicious",
        >= 60 => "High Risk",
        >= 40 => "Suspicious",
        >= 20 => "Low Risk",
        _     => "Likely Clean"
    };
}
