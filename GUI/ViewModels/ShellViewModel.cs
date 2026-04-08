using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Noodle.Core.Models;
using Noodle.Core.Services;

namespace Noodle.App.ViewModels;

public sealed partial class ShellViewModel : ObservableObject
{
    private readonly IAnalysisService _analysis;
    private readonly SettingsViewModel _settingsVm;

    [ObservableProperty] private object  _currentPage = null!;
    [ObservableProperty] private bool    _isHomeActive;
    [ObservableProperty] private bool    _isSettingsActive;

    public ShellViewModel(IAnalysisService analysis, SettingsViewModel settingsVm)
    {
        _analysis   = analysis;
        _settingsVm = settingsVm;
        GoHomeCommand.Execute(null);
    }

    [RelayCommand]
    private void GoHome()
    {
        CurrentPage       = new DropViewModel(_analysis, this);
        IsHomeActive      = true;
        IsSettingsActive  = false;
    }

    [RelayCommand]
    private void GoSettings()
    {
        CurrentPage       = _settingsVm;
        IsHomeActive      = false;
        IsSettingsActive  = true;
    }

    public void NavigateToAnalysis(AnalysisResult result)
    {
        CurrentPage       = new AnalysisViewModel(result, this);
        IsHomeActive      = true;
        IsSettingsActive  = false;
    }
}
