using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GUI.Models;
using Noodle.Library.PE;
using Serilog;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Text;

namespace GUI.ViewModels
{
    public partial class MainViewModel : ObservableObject
    {
        [ObservableProperty]
        private ObservableCollection<string>? labels;

        [ObservableProperty]
        private LogEntry? log;

        private PEService pEService = new PEService();

        public MainViewModel()
        {
            Serilog.Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Debug()
                .WriteTo.Console()
                .WriteTo.Sink(new LogsManager(this))
                .CreateLogger();
        }

        private void RenderLabels(List<string> rawLabels)
        {
        }

        [RelayCommand]
        private void Scan(string path)
        {
            Labels = new ObservableCollection<string>();
            pEService.Update(path);

            Serilog.Log.Information("ici");

            if (pEService.IsPeFile(path) == true)
            {
                pEService.LoadPE();
                List<Noodle.Library.Models.Section> sections = pEService.GetSections();

                foreach (Noodle.Library.Models.Section section in sections)
                {
                    labels.Add(section.Name);
                }
            } else
            {
                Serilog.Log.Error("the file provided is not a binary file");
            }
        }
    }
}
