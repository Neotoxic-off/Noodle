using System.IO;
using System.Text.Json;

namespace Noodle.App.Services;

public sealed class SettingsService : ISettingsService
{
    private record SettingsData(bool IsDarkTheme = true);

    private static readonly string FilePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "Noodle", "settings.json");

    private SettingsData _data;

    public SettingsService()
    {
        _data = Load();
    }

    public bool IsDarkTheme
    {
        get => _data.IsDarkTheme;
        set { _data = _data with { IsDarkTheme = value }; Save(); }
    }

    private static SettingsData Load()
    {
        try
        {
            if (!File.Exists(FilePath)) return new SettingsData();
            var json = File.ReadAllText(FilePath);
            return JsonSerializer.Deserialize<SettingsData>(json) ?? new SettingsData();
        }
        catch { return new SettingsData(); }
    }

    private void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(_data));
        }
        catch { }
    }
}
