using System.Collections.Generic;
using System.Collections.Immutable;
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Noodle.Core.Models;

namespace Noodle.App.ViewModels;

public sealed record DllImportGroup(string DllName, IReadOnlyList<string> Functions);

public sealed record CategoryTag(string Label, string Icon, Severity Severity);

public sealed partial class AnalysisViewModel : ObservableObject
{
    private readonly ShellViewModel _shell;

    public AnalysisResult Result { get; }

    public ObservableCollection<Detection> DangerousDetections { get; }
    public ObservableCollection<Detection> SuspiciousDetections { get; }
    public ObservableCollection<Detection> SafeDetections { get; }
    public ObservableCollection<Detection> InfoDetections { get; }
    public IReadOnlyList<CategoryTag> CategoryTags { get; }
    public IReadOnlyList<YaraRuleResult> MatchedYaraResults { get; }
    public IReadOnlyList<YaraRuleResult> AllYaraResults { get; }

    public bool HasDangerous => DangerousDetections.Count > 0;
    public bool HasSuspicious => SuspiciousDetections.Count > 0;
    public bool HasSafe => SafeDetections.Count > 0;
    public bool HasInfo => InfoDetections.Count > 0;
    public bool HasTags => CategoryTags.Count > 0;
    public bool HasMatchedYara => MatchedYaraResults.Count > 0;
    public bool HasYaraRules => AllYaraResults.Count > 0;
    public System.Windows.Visibility NoYaraMatchesVisibility =>
        HasYaraRules && !HasMatchedYara
            ? System.Windows.Visibility.Visible
            : System.Windows.Visibility.Collapsed;

    public IReadOnlyList<DllImportGroup> ImportsByDll { get; }
    public IReadOnlyList<string> Exports { get; }
    public bool HasImports => ImportsByDll.Count > 0;
    public bool HasExports => Exports.Count > 0;

    public CompilerInfo? Compiler => Result.Compiler;
    public bool HasCompilerInfo => Compiler is not null;

    public NetworkInfo Network => Result.Network;
    public bool HasNetworkData => Result.Network.HasAny;

    public IReadOnlyList<YaraRuleResult> CredentialYaraMatches { get; }
    public bool HasCredentials => CredentialYaraMatches.Count > 0;

    public string OverallLabel => Result.OverallSeverity switch
    {
        Severity.Dangerous => "DANGEROUS",
        Severity.Suspicious => "SUSPICIOUS",
        _ => "CLEAN"
    };
    public Severity OverallSeverity => Result.OverallSeverity;
    public string Verdict => Result.Verdict;
    public int ThreatScore => Result.ThreatScore;

    public AnalysisViewModel(AnalysisResult result, ShellViewModel shell)
    {
        Result = result;
        _shell = shell;

        DangerousDetections = new(result.Detections.Where(d => d.Severity == Severity.Dangerous));
        SuspiciousDetections = new(result.Detections.Where(d => d.Severity == Severity.Suspicious));
        SafeDetections = new(result.Detections.Where(d => d.Severity == Severity.Safe && d.Category != DetectionCategory.Info));
        InfoDetections = new(result.Detections.Where(d => d.Category == DetectionCategory.Info));

        MatchedYaraResults = result.YaraResults.Where(r => r.Matched).ToList();
        AllYaraResults = result.YaraResults.ToList();
        CredentialYaraMatches = result.YaraResults
            .Where(r => r.Matched && r.Name.StartsWith("Credential_", StringComparison.OrdinalIgnoreCase))
            .ToList();
        CategoryTags = BuildCategoryTags(result.Detections);

        ImportsByDll = result.PE?.Imports
            .GroupBy(i => i.DllName, StringComparer.OrdinalIgnoreCase)
            .Select(g => new DllImportGroup(
                g.Key,
                g.Select(i => i.FunctionName).OrderBy(n => n).ToList()))
            .OrderBy(g => g.DllName)
            .ToList() ?? [];

        Exports = result.PE?.Exports.ToList() ?? [];
    }

    [RelayCommand]
    private void ScanAnother() => _shell.GoHomeCommand.Execute(null);

    private static IReadOnlyList<CategoryTag> BuildCategoryTags(
        ImmutableArray<Detection> detections)
    {
        return detections
            .Where(d => d.Category != DetectionCategory.Info)
            .GroupBy(d => d.Category)
            .Select(g =>
            {
                Severity worst = g.Max(d => d.Severity);
                string   icon  = g.Key switch
                {
                    DetectionCategory.Packing => "📦",
                    DetectionCategory.AntiDebug => "🔍",
                    DetectionCategory.Network => "🌐",
                    DetectionCategory.Injection => "💉",
                    DetectionCategory.Crypto => "🔐",
                    DetectionCategory.Keylogger => "⌨",
                    DetectionCategory.Privilege => "⚡",
                    DetectionCategory.Anomaly => "⚠",
                    DetectionCategory.Yara => "🎯",
                    DetectionCategory.AsmPattern => "⚙",
                    DetectionCategory.Signature => "📋",
                    DetectionCategory.Persistence => "📌",
                    DetectionCategory.Evasion => "🎭",
                    DetectionCategory.Ransomware => "💰",
                    DetectionCategory.ScreenCapture => "📸",
                    _ => "ℹ"
                };
                return new CategoryTag(g.Key.ToString(), icon, worst);
            })
            .OrderByDescending(t => t.Severity)
            .ThenBy(t => t.Label)
            .ToList();
    }
}
