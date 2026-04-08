using System.Globalization;
using System.Windows.Data;

namespace Noodle.App.Converters;

public sealed class UnixTimestampConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is long ts && ts > 0)
        {
            try
            {
                var dt = DateTimeOffset.FromUnixTimeSeconds(ts).UtcDateTime;
                return dt.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            }
            catch { }
        }
        return "—";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => Binding.DoNothing;
}
