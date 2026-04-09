using Noodle.Core.Models;

namespace Noodle.Core.Services;

public sealed class ImportAnalyzer
{
    public IEnumerable<Detection> Analyze(IReadOnlyList<ImportEntry> imports)
    {
        return Enumerable.Empty<Detection>();
    }
}
