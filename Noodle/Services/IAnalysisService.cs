using Noodle.Core.Models;

namespace Noodle.Core.Services;

public interface IAnalysisService
{
    Task<AnalysisResult> AnalyzeAsync(
        string filePath,
        IProgress<string>? progress = null,
        CancellationToken ct = default);
}
