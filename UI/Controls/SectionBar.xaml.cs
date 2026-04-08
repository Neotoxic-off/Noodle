using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Noodle.UI.Controls;

public partial class SectionBar : UserControl
{
    public static readonly DependencyProperty SectionNameProperty =
        DependencyProperty.Register(nameof(SectionName), typeof(string), typeof(SectionBar), new PropertyMetadata(string.Empty));

    public static readonly DependencyProperty EntropyProperty =
        DependencyProperty.Register(nameof(Entropy), typeof(double), typeof(SectionBar),
            new PropertyMetadata(0.0, OnEntropyChanged));

    public static readonly DependencyProperty BarMaxWidthProperty =
        DependencyProperty.Register(nameof(BarMaxWidth), typeof(double), typeof(SectionBar),
            new PropertyMetadata(200.0, OnEntropyChanged));

    public static readonly DependencyProperty IsExecutableProperty =
        DependencyProperty.Register(nameof(IsExecutable), typeof(bool), typeof(SectionBar),
            new PropertyMetadata(false, OnFlagsChanged));

    public static readonly DependencyProperty IsWritableProperty =
        DependencyProperty.Register(nameof(IsWritable), typeof(bool), typeof(SectionBar),
            new PropertyMetadata(false, OnFlagsChanged));

    public string SectionName
    {
        get => (string)GetValue(SectionNameProperty);
        set => SetValue(SectionNameProperty, value);
    }

    public double Entropy
    {
        get => (double)GetValue(EntropyProperty);
        set => SetValue(EntropyProperty, value);
    }

    public double BarMaxWidth
    {
        get => (double)GetValue(BarMaxWidthProperty);
        set => SetValue(BarMaxWidthProperty, value);
    }

    public bool IsExecutable
    {
        get => (bool)GetValue(IsExecutableProperty);
        set => SetValue(IsExecutableProperty, value);
    }

    public bool IsWritable
    {
        get => (bool)GetValue(IsWritableProperty);
        set => SetValue(IsWritableProperty, value);
    }

    public Brush   EntropyBrush    { get; private set; } = Brushes.Gray;
    public double  EntropyBarWidth { get; private set; }
    public string  EntropyText     { get; private set; } = "0.00";
    public Visibility ExecVisibility  { get; private set; } = Visibility.Collapsed;
    public Visibility WriteVisibility { get; private set; } = Visibility.Collapsed;

    public SectionBar()
    {
        InitializeComponent();
        UpdateEntropy();
    }

    private static void OnEntropyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        => ((SectionBar)d).UpdateEntropy();

    private static void OnFlagsChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        => ((SectionBar)d).UpdateFlags();

    private void UpdateEntropy()
    {
        double clamped = Math.Clamp(Entropy, 0, 8);
        EntropyBarWidth = (clamped / 8.0) * BarMaxWidth;
        EntropyText     = $"{Entropy:F2}";

        string key = Entropy switch
        {
            >= 7.2 => "Br.Danger",
            >= 6.5 => "Br.Warning",
            _      => "Br.Success"
        };

        EntropyBrush = GetBrush(key);
    }

    private void UpdateFlags()
    {
        ExecVisibility  = IsExecutable ? Visibility.Visible : Visibility.Collapsed;
        WriteVisibility = IsWritable   ? Visibility.Visible : Visibility.Collapsed;
    }

    private static Brush GetBrush(string key)
    {
        if (Application.Current?.Resources.Contains(key) == true
            && Application.Current.Resources[key] is Brush b) return b;
        return Brushes.Gray;
    }
}
