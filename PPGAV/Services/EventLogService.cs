using System.Collections.ObjectModel;
using System.Text.Json;
using PPGAV.Models;

namespace PPGAV.Services;

public sealed record AppEvent(DateTimeOffset Timestamp, ScanCategory Category, string Title, string Detail);

public sealed class EventLogService
{
    private readonly ObservableCollection<AppEvent> _events = [];
    private readonly object _gate = new();

    public EventLogService()
    {
        AppPaths.EnsureDirectories();
        try
        {
            if (File.Exists(AppPaths.EventLogFile))
            {
                foreach (var line in File.ReadLines(AppPaths.EventLogFile).TakeLast(100))
                {
                    var item = JsonSerializer.Deserialize<AppEvent>(line);
                    if (item is not null) _events.Add(item);
                }
            }
        }
        catch
        {
            // Logs are diagnostic only.
        }
    }

    public ReadOnlyObservableCollection<AppEvent> Events => new(_events);
    public event EventHandler<AppEvent>? EventAdded;

    public void Log(string title, string detail, ScanCategory category = ScanCategory.Safe)
    {
        var item = new AppEvent(DateTimeOffset.Now, category, title, detail);
        lock (_gate)
        {
            _events.Add(item);
            while (_events.Count > 200) _events.RemoveAt(0);
            try
            {
                File.AppendAllText(AppPaths.EventLogFile, JsonSerializer.Serialize(item) + Environment.NewLine);
            }
            catch { }
        }

        EventAdded?.Invoke(this, item);
    }
}
