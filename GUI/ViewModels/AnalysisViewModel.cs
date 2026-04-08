using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Noodle.Core.Models;

namespace Noodle.App.ViewModels;

/// <summary>One category summarised as a colored label for the tags cloud.</summary>
public sealed record CategoryTag(string Label, string Icon, Severity Severity);

public sealed partial class AnalysisViewModel : ObservableObject
{
    private readonly ShellViewModel _shell;

    public AnalysisResult Result { get; }

    public ObservableCollection<Detection> DangerousDetections  { get; }
    public ObservableCollection<Detection> SuspiciousDetections { get; }
    public ObservableCollection<Detection> SafeDetections       { get; }
    public ObservableCollection<Detection> InfoDetections       { get; }

    /// <summary>One tag per detection category, ordered worst-first — drives the labels cloud.</summary>
    public IReadOnlyList<CategoryTag> CategoryTags { get; }

    public bool HasDangerous  => DangerousDetections.Count  > 0;
    public bool HasSuspicious => SuspiciousDetections.Count > 0;
    public bool HasSafe       => SafeDetections.Count       > 0;
    public bool HasInfo       => InfoDetections.Count       > 0;
    public bool HasTags       => CategoryTags.Count         > 0;

    public string OverallLabel => Result.OverallSeverity switch
    {
        Severity.Dangerous  => "DANGEROUS",
        Severity.Suspicious => "SUSPICIOUS",
        _                   => "CLEAN"
    };

    public Severity OverallSeverity => Result.OverallSeverity;

    public string  Verdict     => Result.Verdict;
    public int     ThreatScore => Result.ThreatScore;

    /// <summary>Score as a [0..1] fraction for the progress bar.</summary>
    public double ThreatScoreFraction => ThreatScore / 100.0;

    public AnalysisViewModel(AnalysisResult result, ShellViewModel shell)
    {
        Result = result;
        _shell = shell;

        DangerousDetections  = new(result.Detections.Where(d => d.Severity == Severity.Dangerous));
        SuspiciousDetections = new(result.Detections.Where(d => d.Severity == Severity.Suspicious));
        SafeDetections       = new(result.Detections.Where(d => d.Severity == Severity.Safe && d.Category != DetectionCategory.Info));
        InfoDetections       = new(result.Detections.Where(d => d.Category == DetectionCategory.Info));

        CategoryTags = BuildCategoryTags(result.Detections);
    }

    [RelayCommand]
    private void ScanAnother() => _shell.GoHomeCommand.Execute(null);

    private static IReadOnlyList<CategoryTag> BuildCategoryTags(
        System.Collections.Immutable.ImmutableArray<Detection> detections)
    {
        return detections
            .Where(d => d.Category != DetectionCategory.Info)   // info tags are too noisy
            .GroupBy(d => d.Category)
            .Select(g =>
            {
                var worst = g.Max(d => d.Severity);
                string icon = g.Key switch
                {
                    DetectionCategory.Packing       => "📦",
                    DetectionCategory.AntiDebug     => "🔍",
                    DetectionCategory.Network       => "🌐",
                    DetectionCategory.Injection     => "💉",
                    DetectionCategory.Crypto        => "🔐",
                    DetectionCategory.Keylogger     => "⌨",
                    DetectionCategory.Privilege     => "⚡",
                    DetectionCategory.Anomaly       => "⚠",
                    DetectionCategory.Yara          => "🎯",
                    DetectionCategory.AsmPattern    => "⚙",
                    DetectionCategory.Signature     => "📋",
                    DetectionCategory.Persistence   => "📌",
                    DetectionCategory.Evasion       => "🎭",
                    DetectionCategory.Ransomware    => "💰",
                    DetectionCategory.ScreenCapture => "📸",
                    _                               => "ℹ"
                };
                return new CategoryTag(g.Key.ToString(), icon, worst);
            })
            .OrderByDescending(t => t.Severity)
            .ThenBy(t => t.Label)
            .ToList();
    }
}
