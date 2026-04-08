using CommunityToolkit.Mvvm.ComponentModel;
using Noodle.App.Services;

namespace Noodle.App.ViewModels;

public sealed partial class SettingsViewModel : ObservableObject
{
    private readonly ISettingsService _settings;

    [ObservableProperty] private bool _isDarkTheme;

    public string Version => typeof(SettingsViewModel).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";

    public SettingsViewModel(ISettingsService settings)
    {
        _settings   = settings;
        _isDarkTheme = settings.IsDarkTheme;
    }

    partial void OnIsDarkThemeChanged(bool value)
    {
        _settings.IsDarkTheme = value;
        ThemeManager.Instance.Apply(value);
    }
}
