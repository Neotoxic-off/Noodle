using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Noodle.Core.Models;
using Noodle.Core.Services;

namespace Noodle.App.ViewModels;

public sealed partial class ShellViewModel : ObservableObject
{
    private readonly IAnalysisService _analysis;

    [ObservableProperty] private object _currentPage = null!;

    public ShellViewModel(IAnalysisService analysis)
    {
        _analysis = analysis;
        GoHomeCommand.Execute(null);
    }

    [RelayCommand]
    private void GoHome() => CurrentPage = new DropViewModel(_analysis, this);

    public void NavigateToAnalysis(AnalysisResult result)
        => CurrentPage = new AnalysisViewModel(result, this);
}
