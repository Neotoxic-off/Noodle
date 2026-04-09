using Noodle.Core.Models;

namespace Noodle.Core.Services;

public readonly record struct ScanProgress(
    string Message,
    int    Step,
    int    TotalSteps,
    int    SubStep      = 0,
    int    SubTotalSteps = 0)
{
    public double Percent    => TotalSteps    > 0 ? (double)Step    / TotalSteps    * 100.0 : 0;
    public double SubPercent => SubTotalSteps > 0 ? (double)SubStep / SubTotalSteps * 100.0 : 0;
    public bool   HasSub     => SubTotalSteps > 0;
}

public interface IAnalysisService
{
    Task<AnalysisResult> AnalyzeAsync(
        string filePath,
        IProgress<ScanProgress>? progress = null,
        CancellationToken ct = default);
}
