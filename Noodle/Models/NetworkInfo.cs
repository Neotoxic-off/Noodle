namespace Noodle.Core.Models;

public sealed record NetworkInfo(
    IReadOnlyList<string> Urls,
    IReadOnlyList<string> Ips,
    IReadOnlyList<string> Emails,
    IReadOnlyList<string> MacAddresses
)
{
    public static readonly NetworkInfo Empty = new([], [], [], []);

    public bool HasAny =>
        Urls.Count > 0 || Ips.Count > 0 || Emails.Count > 0 || MacAddresses.Count > 0;
}
