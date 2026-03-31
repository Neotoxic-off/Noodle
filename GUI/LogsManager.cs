using GUI;
using GUI.Models;
using GUI.ViewModels;
using Serilog.Core;
using Serilog.Events;

public class LogsManager : ILogEventSink
{
    private readonly MainViewModel _viewModel;

    public LogsManager(MainViewModel viewModel)
    {
        _viewModel = viewModel;
    }

    public void Emit(LogEvent logEvent)
    {
        LogEntry entry = new LogEntry
        {
            Level = logEvent.Level.ToString(),
            Message = logEvent.RenderMessage()
        };

        App.Current.Dispatcher.Invoke(() =>
        {
            _viewModel.Log = entry;
        });
    }
}
