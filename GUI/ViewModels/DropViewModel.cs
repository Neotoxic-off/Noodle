using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Noodle.Core.Services;
using System.IO;

namespace Noodle.App.ViewModels;

public sealed partial class DropViewModel : ObservableObject
{
    private readonly IAnalysisService _analysis;
    private readonly ShellViewModel   _shell;

    [ObservableProperty] private bool   _isAnalyzing;
    [ObservableProperty] private string _statusText = "DROP ANY FILE TO ANALYZE";
    [ObservableProperty] private bool   _hasError;
    [ObservableProperty] private string _errorText  = string.Empty;

    public DropViewModel(IAnalysisService analysis, ShellViewModel shell)
    {
        _analysis = analysis;
        _shell    = shell;
    }

    [RelayCommand]
    private async Task DropFileAsync(string path)
    {
        HasError    = false;
        IsAnalyzing = true;
        StatusText  = $"// {Path.GetFileName(path)}";

        var progress = new Progress<string>(msg => StatusText = msg);

        try
        {
            var result = await _analysis.AnalyzeAsync(path, progress);
            _shell.NavigateToAnalysis(result);
        }
        catch (Exception ex)
        {
            HasError   = true;
            ErrorText  = ex.Message;
            StatusText = "[ERROR] Analysis failed";
        }
        finally
        {
            IsAnalyzing = false;
        }
    }

    [RelayCommand]
    private async Task BrowseFileAsync()
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title  = "Select a file to analyze",
            Filter = "All files (*.*)|*.*"
        };
        if (dlg.ShowDialog() == true)
            await DropFileAsync(dlg.FileName);
    }
}
