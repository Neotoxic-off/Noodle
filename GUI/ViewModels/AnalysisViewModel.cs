using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Noodle.Core.Models;

namespace Noodle.App.ViewModels;

public sealed partial class AnalysisViewModel : ObservableObject
{
    private readonly ShellViewModel _shell;

    public AnalysisResult Result { get; }

    public ObservableCollection<Detection> DangerousDetections  { get; }
    public ObservableCollection<Detection> SuspiciousDetections { get; }
    public ObservableCollection<Detection> SafeDetections       { get; }
    public ObservableCollection<Detection> InfoDetections       { get; }

    public bool HasDangerous  => DangerousDetections.Count  > 0;
    public bool HasSuspicious => SuspiciousDetections.Count > 0;
    public bool HasSafe       => SafeDetections.Count       > 0;
    public bool HasInfo       => InfoDetections.Count       > 0;

    public string OverallLabel => Result.OverallSeverity switch
    {
        Severity.Dangerous  => "DANGEROUS",
        Severity.Suspicious => "SUSPICIOUS",
        _                   => "CLEAN"
    };

    public Severity OverallSeverity => Result.OverallSeverity;

    public AnalysisViewModel(AnalysisResult result, ShellViewModel shell)
    {
        Result = result;
        _shell = shell;

        DangerousDetections  = new(result.Detections.Where(d => d.Severity == Severity.Dangerous));
        SuspiciousDetections = new(result.Detections.Where(d => d.Severity == Severity.Suspicious));
        SafeDetections       = new(result.Detections.Where(d => d.Severity == Severity.Safe && d.Category != DetectionCategory.Info));
        InfoDetections       = new(result.Detections.Where(d => d.Category == DetectionCategory.Info));
    }

    [RelayCommand]
    private void ScanAnother() => _shell.GoHomeCommand.Execute(null);
}
