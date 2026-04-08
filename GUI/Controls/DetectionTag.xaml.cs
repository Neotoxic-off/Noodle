using Noodle.Core.Models;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Noodle.App.Controls;

public partial class DetectionTag : UserControl
{
    // ── Public DP: caller sets these ─────────────────────────────────────────

    public static readonly DependencyProperty LabelProperty =
        DependencyProperty.Register(nameof(Label), typeof(string), typeof(DetectionTag),
            new PropertyMetadata(string.Empty));

    public static readonly DependencyProperty SeverityProperty =
        DependencyProperty.Register(nameof(Severity), typeof(object), typeof(DetectionTag),
            new PropertyMetadata(null, OnSeverityChanged));

    // ── Internal DP: bound from XAML, written from UpdateVisuals ─────────────
    // Must be DependencyProperties so that SetValue() triggers binding refresh.

    public static readonly DependencyProperty TagForegroundProperty =
        DependencyProperty.Register(nameof(TagForeground), typeof(Brush), typeof(DetectionTag),
            new PropertyMetadata(Brushes.White));

    public static readonly DependencyProperty TagBackgroundProperty =
        DependencyProperty.Register(nameof(TagBackground), typeof(Brush), typeof(DetectionTag),
            new PropertyMetadata(Brushes.Transparent));

    public static readonly DependencyProperty TagBorderBrushProperty =
        DependencyProperty.Register(nameof(TagBorderBrush), typeof(Brush), typeof(DetectionTag),
            new PropertyMetadata(Brushes.Gray));

    // ── CLR wrappers ─────────────────────────────────────────────────────────

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

    public Brush TagForeground
    {
        get => (Brush)GetValue(TagForegroundProperty);
        private set => SetValue(TagForegroundProperty, value);
    }

    public Brush TagBackground
    {
        get => (Brush)GetValue(TagBackgroundProperty);
        private set => SetValue(TagBackgroundProperty, value);
    }

    public Brush TagBorderBrush
    {
        get => (Brush)GetValue(TagBorderBrushProperty);
        private set => SetValue(TagBorderBrushProperty, value);
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

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
            Noodle.Core.Models.Severity.Dangerous  => (Brush("Br.Danger"),  Brush("Br.DangerBg"),  Brush("Br.Danger")),
            Noodle.Core.Models.Severity.Suspicious => (Brush("Br.Warning"), Brush("Br.WarningBg"), Brush("Br.Warning")),
            _                                      => (Brush("Br.Success"), Brush("Br.SuccessBg"), Brush("Br.Success")),
        };
    }

    private static Brush Brush(string key)
    {
        if (Application.Current?.Resources.Contains(key) == true
            && Application.Current.Resources[key] is Brush b) return b;
        return Brushes.Gray;
    }
}
