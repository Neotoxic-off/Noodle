using Noodle.Core.Models;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Noodle.App.Controls;

public partial class DetectionTag : UserControl
{
    public static readonly DependencyProperty LabelProperty =
        DependencyProperty.Register(nameof(Label), typeof(string), typeof(DetectionTag), new PropertyMetadata(string.Empty));

    // Typed as object so the BAML compiler doesn't need Noodle.Core.dll at XAML compile time.
    // Accepts Severity enum values via WPF binding at runtime.
    public static readonly DependencyProperty SeverityProperty =
        DependencyProperty.Register(nameof(Severity), typeof(object), typeof(DetectionTag),
            new PropertyMetadata(null, OnSeverityChanged));

    public string Label
    {
        get => (string)GetValue(LabelProperty);
        set => SetValue(LabelProperty, value);
    }

    public object? Severity
    {
        get => GetValue(SeverityProperty);
        set => SetValue(SeverityProperty, value);
    }

    public Brush TagForeground  { get; private set; } = Brushes.White;
    public Brush TagBackground  { get; private set; } = Brushes.Transparent;
    public Brush TagBorderBrush { get; private set; } = Brushes.Gray;

    public DetectionTag()
    {
        InitializeComponent();
        UpdateVisuals();
    }

    private static void OnSeverityChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        => ((DetectionTag)d).UpdateVisuals();

    private void UpdateVisuals()
    {
        var severity = Severity is Noodle.Core.Models.Severity s ? s : Noodle.Core.Models.Severity.Safe;

        (TagForeground, TagBackground, TagBorderBrush) = severity switch
        {
            Noodle.Core.Models.Severity.Dangerous  => (GetBrush("Br.Danger"),  GetBrush("Br.DangerBg"),  GetBrush("Br.Danger")),
            Noodle.Core.Models.Severity.Suspicious => (GetBrush("Br.Warning"), GetBrush("Br.WarningBg"), GetBrush("Br.Warning")),
            _                                      => (GetBrush("Br.Success"), GetBrush("Br.SuccessBg"), GetBrush("Br.Success")),
        };
    }

    private static Brush GetBrush(string key)
    {
        if (Application.Current?.Resources.Contains(key) == true
            && Application.Current.Resources[key] is Brush b) return b;
        return Brushes.Gray;
    }
}
