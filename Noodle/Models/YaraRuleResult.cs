namespace Noodle.Core.Models;

public sealed record YaraRuleResult(string Name, string Description, Severity Severity, bool Matched);
