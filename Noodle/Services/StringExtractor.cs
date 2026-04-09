using System.Text;
using System.Text.RegularExpressions;
using Noodle.Core.Models;

namespace Noodle.Core.Services;

public sealed class StringExtractor
{
    private static readonly Regex UrlRegex    = new(@"https?://[^\s""'<>]{8,}", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex IpRegex     = new(@"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b", RegexOptions.Compiled);
    private static readonly Regex Base64Regex = new(@"[A-Za-z0-9+/]{40,}={0,2}", RegexOptions.Compiled);

    private const int MinStringLen   = 6;
    private const int MaxBytesToScan = 4 * 1024 * 1024;

    public IEnumerable<Detection> Analyze(string filePath)
    {
        string[]     strings = [];
        List<string> urls    = [];
        List<string> ips     = [];
        List<string> b64     = [];

        if (!File.Exists(filePath)) yield break;

        strings = ExtractStrings(filePath);
        urls    = strings.Where(s => UrlRegex.IsMatch(s)).Distinct().Take(10).ToList();
        ips     = strings.Where(s => IpRegex.IsMatch(s) && !IsPrivateIp(s)).Distinct().Take(10).ToList();
        b64     = strings.Where(s => Base64Regex.IsMatch(s)).Take(5).ToList();

        if (urls.Count > 0)
            yield return new Detection(
                "Embedded URLs",
                $"Found {urls.Count} hardcoded URL(s): {string.Join(", ", urls.Take(3))}",
                Severity.Suspicious,
                DetectionCategory.Network
            );

        if (ips.Count > 0)
            yield return new Detection(
                "Hardcoded IP Addresses",
                $"Found {ips.Count} public IP address(es): {string.Join(", ", ips.Take(3))}",
                Severity.Suspicious,
                DetectionCategory.Network
            );

        if (b64.Count > 0)
            yield return new Detection(
                "Base64 Encoded Data",
                "Contains long Base64-encoded strings — may hide shellcode or config.",
                Severity.Suspicious,
                DetectionCategory.Anomaly
            );
    }

    private static string[] ExtractStrings(string filePath)
    {
        FileStream    fs      = File.OpenRead(filePath);
        byte[]        buf     = new byte[Math.Min(fs.Length, MaxBytesToScan)];
        List<string>  results = new List<string>();
        StringBuilder current = new StringBuilder();

        fs.ReadExactly(buf);
        fs.Dispose();

        for (int i = 0; i < buf.Length; i = i + 1)
        {
            byte b = buf[i];

            if (b >= 0x20 && b < 0x7F)
            {
                current.Append((char)b);
            }
            else
            {
                if (current.Length >= MinStringLen)
                    results.Add(current.ToString());
                current.Clear();
            }
        }

        if (current.Length >= MinStringLen)
            results.Add(current.ToString());

        return results.ToArray();
    }

    private static bool IsPrivateIp(string s)
    {
        Match m = Regex.Match(s, @"(\d+)\.(\d+)\.");
        int   a = 0;
        int   b = 0;

        if (!m.Success) return false;

        a = int.Parse(m.Groups[1].Value);
        b = int.Parse(m.Groups[2].Value);

        return a == 10 || a == 127 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168);
    }
}
