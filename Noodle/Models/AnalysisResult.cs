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
}
