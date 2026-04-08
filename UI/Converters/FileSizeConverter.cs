using System.Globalization;
using System.Windows.Data;

namespace Noodle.UI.Converters;

public sealed class FileSizeConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is not long size) return "0 B";
        return size switch
        {
            < 1024                => $"{size} B",
            < 1024 * 1024         => $"{size / 1024.0:F1} KB",
            < 1024 * 1024 * 1024L => $"{size / 1024.0 / 1024.0:F2} MB",
            _                     => $"{size / 1024.0 / 1024.0 / 1024.0:F2} GB"
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => Binding.DoNothing;
}
