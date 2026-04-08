using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Noodle.Core.Models;

namespace Noodle.UI.Controls;

public partial class DetectionTag : UserControl
{
    public static readonly DependencyProperty LabelProperty =
        DependencyProperty.Register(nameof(Label), typeof(string), typeof(DetectionTag), new PropertyMetadata(string.Empty));

    public static readonly DependencyProperty SeverityProperty =
        DependencyProperty.Register(nameof(Severity), typeof(Severity), typeof(DetectionTag),
            new PropertyMetadata(Severity.Safe, OnSeverityChanged));

    public string Label
    {
        get => (string)GetValue(LabelProperty);
        set => SetValue(LabelProperty, value);
    }

    public Severity Severity
    {
        get => (Severity)GetValue(SeverityProperty);
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
        (TagForeground, TagBackground, TagBorderBrush) = Severity switch
        {
            Severity.Dangerous  => (GetBrush("Br.Danger"),  GetBrush("Br.DangerBg"),  GetBrush("Br.Danger")),
            Severity.Suspicious => (GetBrush("Br.Warning"), GetBrush("Br.WarningBg"), GetBrush("Br.Warning")),
            _                   => (GetBrush("Br.Success"), GetBrush("Br.SuccessBg"), GetBrush("Br.Success")),
        };
    }

    private static Brush GetBrush(string key)
    {
        if (Application.Current?.Resources.Contains(key) == true
            && Application.Current.Resources[key] is Brush b) return b;
        return Brushes.Gray;
    }
}
