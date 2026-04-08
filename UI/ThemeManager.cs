using System.Windows;

namespace Noodle.UI;

public sealed class ThemeManager
{
    public static ThemeManager Instance { get; } = new();
    private ThemeManager() { }

    public bool IsDark { get; private set; } = true;

    public void Apply(bool dark)
    {
        IsDark = dark;
        var dicts = Application.Current.Resources.MergedDictionaries;
        var toRemove = dicts.Where(d => d.Source?.OriginalString.Contains("/Themes/") == true).ToList();
        foreach (var d in toRemove) dicts.Remove(d);

        var uri = new Uri(dark
            ? "pack://application:,,,/Noodle.UI;component/Themes/Dark.xaml"
            : "pack://application:,,,/Noodle.UI;component/Themes/Light.xaml");

        dicts.Add(new ResourceDictionary { Source = uri });
    }

    public void Toggle() => Apply(!IsDark);
}
