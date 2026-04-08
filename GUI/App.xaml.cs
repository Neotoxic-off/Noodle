using Microsoft.Extensions.DependencyInjection;
using Noodle.App.Services;
using Noodle.App.ViewModels;
using Noodle.Core.Services;
using System.Windows;

namespace Noodle.App;

public partial class App : Application
{
    private ServiceProvider _provider = null!;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var sc = new ServiceCollection();
        sc.AddSingleton<IAnalysisService, AnalysisService>();
        sc.AddSingleton<ISettingsService, SettingsService>();
        sc.AddSingleton<SettingsViewModel>();
        sc.AddSingleton<ShellViewModel>();
        _provider = sc.BuildServiceProvider();

        var settings = _provider.GetRequiredService<ISettingsService>();
        ThemeManager.Instance.Apply(settings.IsDarkTheme);

        var shell = _provider.GetRequiredService<ShellViewModel>();
        new MainWindow { DataContext = shell }.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _provider.Dispose();
        base.OnExit(e);
    }
}
