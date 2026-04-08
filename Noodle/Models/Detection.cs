namespace Noodle.Core.Models;

public sealed record Detection(
    string Name,
    string Description,
    Severity Severity,
    DetectionCategory Category
);
