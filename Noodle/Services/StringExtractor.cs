using System.Text;
using System.Text.RegularExpressions;
using Noodle.Core.Models;

namespace Noodle.Core.Services;

public sealed class StringExtractor
{
    private static readonly Regex UrlRegex = new(
        @"https?://[^\s""'<>]{8,}",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex IpRegex = new(
        @"(?<![=.""\w])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?::\d{1,5})?(?![.\d])",
        RegexOptions.Compiled);

    private static readonly Regex MacRegex = new(
        @"(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}",
        RegexOptions.Compiled);

    private static readonly Regex EmailRegex = new(
        @"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,6}",
        RegexOptions.Compiled);

    private static readonly Regex Base64Regex = new(
        @"[A-Za-z0-9+/]{40,}={0,2}",
        RegexOptions.Compiled);

    private const int MinStringLen = 6;
    private const int MaxBytesToScan = 4 * 1024 * 1024;

    public (IEnumerable<Detection> Detections, NetworkInfo Network) Analyze(string filePath)
    {
        if (!File.Exists(filePath))
            return (Enumerable.Empty<Detection>(), NetworkInfo.Empty);

        string[] strings = ExtractStrings(filePath);

        List<string> urls = strings
            .SelectMany(s => UrlRegex.Matches(s).Select(m => m.Value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(50)
            .ToList();

        List<string> allIps = strings
            .SelectMany(s => IpRegex.Matches(s).Select(m => m.Value))
            .Distinct()
            .Take(100)
            .ToList();

        List<string> publicIps = allIps
            .Where(ip => !IsPrivateIp(ip))
            .ToList();

        List<string> emails = strings
            .SelectMany(s => EmailRegex.Matches(s).Select(m => m.Value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(50)
            .ToList();

        List<string> macs = strings
            .SelectMany(s => MacRegex.Matches(s).Select(m => m.Value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(50)
            .ToList();

        List<string> b64 = strings
            .Where(s => Base64Regex.IsMatch(s))
            .Take(5)
            .ToList();

        NetworkInfo network = new NetworkInfo(urls, allIps, emails, macs);

        List<Detection> detections = new List<Detection>();

        if (urls.Count > 0)
            detections.Add(new Detection(
                "Embedded URLs",
                $"Found {urls.Count} hardcoded URL(s): {string.Join(", ", urls.Take(3))}",
                Severity.Suspicious,
                DetectionCategory.Network));

        if (publicIps.Count > 0)
            detections.Add(new Detection(
                "Hardcoded IP Addresses",
                $"Found {publicIps.Count} public IP address(es): {string.Join(", ", publicIps.Take(3))}",
                Severity.Suspicious,
                DetectionCategory.Network));

        if (emails.Count > 0)
            detections.Add(new Detection(
                "Embedded Email Addresses",
                $"Found {emails.Count} email address(es): {string.Join(", ", emails.Take(3))}",
                Severity.Suspicious,
                DetectionCategory.Network));

        if (macs.Count > 0)
            detections.Add(new Detection(
                "Hardcoded MAC Addresses",
                $"Found {macs.Count} MAC address(es): {string.Join(", ", macs.Take(3))}",
                Severity.Suspicious,
                DetectionCategory.Network));

        if (b64.Count > 0)
            detections.Add(new Detection(
                "Base64 Encoded Data",
                "Contains long Base64-encoded strings — may hide shellcode or config.",
                Severity.Suspicious,
                DetectionCategory.Anomaly));

        return (detections, network);
    }

    private static string[] ExtractStrings(string filePath)
    {
        FileStream fs = File.OpenRead(filePath);
        byte[] buf = new byte[Math.Min(fs.Length, MaxBytesToScan)];
        List<string> results = new List<string>();
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
        Match m = Regex.Match(s, @"^(\d+)\.(\d+)\.");
        int a = 0;
        int b = 0;

        if (!m.Success) return false;

        a = int.Parse(m.Groups[1].Value);
        b = int.Parse(m.Groups[2].Value);

        return a == 10 || a == 127 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168);
    }
}
