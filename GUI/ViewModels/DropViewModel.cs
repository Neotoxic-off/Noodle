using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Noodle.Core.Models;
using Noodle.Core.Services;
using System.IO;

namespace Noodle.App.ViewModels;

public sealed partial class DropViewModel : ObservableObject
{
    private readonly IAnalysisService _analysis;
    private readonly ShellViewModel   _shell;

    [ObservableProperty] private bool _isAnalyzing;
    [ObservableProperty] private string _statusText = "DROP ANY FILE TO ANALYZE";
    [ObservableProperty] private bool _hasError;
    [ObservableProperty] private string _errorText = string.Empty;
    [ObservableProperty] private double _scanProgress;
    [ObservableProperty] private double _subScanProgress;
    [ObservableProperty] private bool _hasSubProgress;
    [ObservableProperty] private string _subStatusText = string.Empty;

    public DropViewModel(IAnalysisService analysis, ShellViewModel shell)
    {
        _analysis = analysis;
        _shell = shell;
    }

    [RelayCommand]
    private async Task DropFileAsync(string path)
    {
        Progress<ScanProgress> progress = new Progress<ScanProgress>(sp =>
        {
            StatusText = sp.Message;
            ScanProgress = sp.Percent;
            HasSubProgress = sp.HasSub;
            SubScanProgress = sp.SubPercent;
            SubStatusText = sp.HasSub ? $"{sp.SubStep} / {sp.SubTotalSteps}" : string.Empty;
        });
        Task<AnalysisResult> analysisTask = null!;

        HasError = false;
        IsAnalyzing = true;
        ScanProgress = 0;
        StatusText = $"// {Path.GetFileName(path)}";

        analysisTask = _analysis.AnalyzeAsync(path, progress);

        await analysisTask.ContinueWith(t =>
        {
            IsAnalyzing = false;

            if (t.IsFaulted)
            {
                HasError = true;
                ErrorText = t.Exception?.InnerException?.Message ?? "Unknown error";
                StatusText = "Analysis failed";
                return;
            }

            _shell.NavigateToAnalysis(t.Result);

        }, TaskScheduler.FromCurrentSynchronizationContext());
    }

    [RelayCommand]
    private async Task BrowseFileAsync()
    {
        Microsoft.Win32.OpenFileDialog dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Select a file to analyze",
            Filter = "All files (*.*)|*.*"
        };

        if (dlg.ShowDialog() == true)
        {
            await DropFileAsync(dlg.FileName);
        }
    }
}
