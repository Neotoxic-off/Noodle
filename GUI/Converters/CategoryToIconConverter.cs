using Noodle.Core.Models;
using System.Globalization;
using System.Windows.Data;

namespace Noodle.App.Converters;

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
            DetectionCategory.Keylogger => "⌨",
            DetectionCategory.Privilege => "⚡",
            DetectionCategory.Anomaly   => "⚠",
            DetectionCategory.Yara      => "🎯",
            _                           => "ℹ"
        } : "ℹ";

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => Binding.DoNothing;
}
