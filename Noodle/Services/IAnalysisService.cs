using Noodle.Core.Models;

namespace Noodle.Core.Services;

public interface IAnalysisService
{
    Task<AnalysisResult> AnalyzeAsync(string filePath, CancellationToken ct = default);
}
