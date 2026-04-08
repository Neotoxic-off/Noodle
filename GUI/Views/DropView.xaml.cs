using Noodle.App.ViewModels;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;

namespace Noodle.App.Views;

public partial class DropView : UserControl
{
    public DropView() => InitializeComponent();

    private void OnDrop(object sender, DragEventArgs e)
    {
        ResetDropStyle();
        if (e.Data.GetData(DataFormats.FileDrop) is string[] { Length: > 0 } files
            && DataContext is DropViewModel vm)
            vm.DropFileCommand.Execute(files[0]);
    }

    private void OnDragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop)
            ? DragDropEffects.Copy
            : DragDropEffects.None;
        e.Handled = true;
    }

    private void OnDragEnter(object sender, DragEventArgs e)
    {
        if (!e.Data.GetDataPresent(DataFormats.FileDrop)) return;
        if (FindName("DropRect") is Rectangle r)
        {
            r.Stroke = Application.Current.Resources["Br.DropBorderHover"] as Brush ?? r.Stroke;
            r.Fill   = Application.Current.Resources["Br.DropBgHover"]     as Brush ?? r.Fill;
        }
    }

    private void OnDragLeave(object sender, DragEventArgs e) => ResetDropStyle();

    private void ResetDropStyle()
    {
        if (FindName("DropRect") is Rectangle r)
        {
            r.Stroke = Application.Current.Resources["Br.DropBorder"] as Brush ?? r.Stroke;
            r.Fill   = Application.Current.Resources["Br.DropBg"]     as Brush ?? r.Fill;
        }
    }
}
