using Noodle.Core.Models;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace Noodle.App.Converters;

public sealed class SeverityToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        string key = value is Severity s ? s switch
        {
            Severity.Dangerous  => "Br.Danger",
            Severity.Suspicious => "Br.Warning",
            _                   => "Br.Info"
        } : "Br.Info";
        return Application.Current?.Resources[key] as Brush ?? Brushes.Gray;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => Binding.DoNothing;
}

public sealed class SeverityToBgBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        string key = value is Severity s ? s switch
        {
            Severity.Dangerous  => "Br.DangerBg",
            Severity.Suspicious => "Br.WarningBg",
            _                   => "Br.InfoBg"
        } : "Br.InfoBg";
        return Application.Current?.Resources[key] as Brush ?? Brushes.Transparent;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => Binding.DoNothing;
}
