using System.Globalization;
using System.Windows.Data;
using Noodle.Core.Models;

namespace Noodle.UI.Converters;

public sealed class CategoryToIconConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => value is DetectionCategory c ? c switch
        {
            DetectionCategory.Packing   => "📦",
            DetectionCategory.AntiDebug => "🔍",
            DetectionCategory.Network   => "🌐",
            DetectionCategory.Injection => "💉",
            DetectionCategory.Crypto    => "🔐",
            DetectionCategory.Keylogger => "⌨️",
            DetectionCategory.Privilege => "⚡",
            DetectionCategory.Anomaly   => "⚠️",
            DetectionCategory.Yara      => "🎯",
            _                           => "ℹ️"
        } : "ℹ️";

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => Binding.DoNothing;
}
