using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using Noodle.Core.Models;

namespace Noodle.UI.Converters;

public sealed class SeverityToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        string key = value is Severity s ? s switch
        {
            Severity.Dangerous  => "Br.Danger",
            Severity.Suspicious => "Br.Warning",
            _                   => "Br.Success"
        } : "Br.Success";

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
            _                   => "Br.SuccessBg"
        } : "Br.SuccessBg";

        return Application.Current?.Resources[key] as Brush ?? Brushes.Transparent;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => Binding.DoNothing;
}
