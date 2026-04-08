using System.Text;
using System.Text.RegularExpressions;
using Noodle.Core.Models;

namespace Noodle.Core.Services;

/// <summary>
/// Two-part scanner:
/// 1. Built-in signature rules (byte patterns + string patterns).
/// 2. Custom YARA rules loaded from the YaraRules/ folder next to the executable.
///    Supports a practical subset: string defs ($a = "text", $b = { hex }),
///    and conditions: any/all of them, $name, $a and $b, $a or $b, not $name.
/// </summary>
public sealed class YaraScanner
{
    // ── Rules folder ──────────────────────────────────────────────────────────

    private static readonly string RulesDir =
        Path.Combine(AppContext.BaseDirectory, "YaraRules");

    public int RuleFileCount { get; }

    private readonly IReadOnlyList<ParsedYaraRule> _customRules;

    public YaraScanner()
    {
        EnsureRulesFolder();
        var files = Directory.GetFiles(RulesDir, "*.yar", SearchOption.AllDirectories)
            .Concat(Directory.GetFiles(RulesDir, "*.yara", SearchOption.AllDirectories))
            .ToArray();
        RuleFileCount = files.Length;
        _customRules  = files.SelectMany(ParseRuleFile).ToList();
    }

    private static void EnsureRulesFolder()
    {
        if (!Directory.Exists(RulesDir))
        {
            Directory.CreateDirectory(RulesDir);
            File.WriteAllText(Path.Combine(RulesDir, "HOWTO.txt"),
                """
                Place YARA rule files (.yar / .yara) in this folder.
                Noodle loads them automatically on startup.

                Supported syntax:

                    rule MyRule {
                        strings:
                            $a = "suspicious string"
                            $b = "another" nocase
                            $c = { 4D 5A 90 00 ?? ?? }
                        condition:
                            any of them
                    }

                Condition keywords: any of them | all of them
                                    $name | $a and $b | $a or $b | not $name

                Rules produce a YARA detection with Suspicious severity by default.
                Add a comment line  // severity: dangerous  above the rule keyword
                to override. Example:

                    // severity: dangerous
                    rule CobaltStrikeBeacon { ... }
                """);
        }
    }

    // ── Built-in byte-pattern rules ───────────────────────────────────────────

    private sealed record ByteRule(
        string Name, string Description, Severity Severity, DetectionCategory Category,
        byte[] Pattern);

    private static readonly ByteRule[] BuiltinByteRules =
    [
        new("UPX Packer",
            "UPX magic bytes ('UPX!') detected — binary is UPX-packed.",
            Severity.Dangerous, DetectionCategory.Packing, "UPX!"u8.ToArray()),

        new("VMProtect",
            "VMProtect signature detected — binary is protected with virtual-machine obfuscation.",
            Severity.Dangerous, DetectionCategory.Packing, "VMProtect"u8.ToArray()),

        new("Themida / WinLicense",
            "Themida/WinLicense protector signature detected.",
            Severity.Dangerous, DetectionCategory.Packing, "Themida"u8.ToArray()),

        new("ASPack",
            "ASPack packer signature detected.",
            Severity.Dangerous, DetectionCategory.Packing, "ASPack"u8.ToArray()),

        new("AES S-box Constants",
            "AES S-box lookup table detected — binary implements AES encryption internally.",
            Severity.Suspicious, DetectionCategory.Crypto,
            [0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76]),

        new("Metasploit Meterpreter",
            "Meterpreter payload string detected — likely a Metasploit reverse-shell payload.",
            Severity.Dangerous, DetectionCategory.Injection, "Meterpreter"u8.ToArray()),

        new("Reflective DLL Loading",
            "'ReflectiveDll' marker detected — binary uses reflective injection to load itself without touching disk.",
            Severity.Dangerous, DetectionCategory.Injection, "ReflectiveDll"u8.ToArray()),

        new("EICAR Test Signature",
            "EICAR anti-virus test file signature detected.",
            Severity.Suspicious, DetectionCategory.Signature,
            "X5O!P%@AP[4\\"u8.ToArray()),
    ];

    // ── Built-in string-pattern rules ─────────────────────────────────────────

    private sealed record StringRule(
        string Name, string Description, Severity Severity, DetectionCategory Category,
        string[] Patterns, bool IgnoreCase = true);

    private static readonly StringRule[] BuiltinStringRules =
    [
        new("AutoRun Registry Persistence",
            "Windows Run/RunOnce registry key path found — binary may add itself to startup.",
            Severity.Suspicious, DetectionCategory.Persistence,
            ["CurrentVersion\\Run", "CurrentVersion\\RunOnce"]),

        new("Scheduled Task Persistence",
            "Task Scheduler COM strings found — binary may install a persistent scheduled task.",
            Severity.Suspicious, DetectionCategory.Persistence,
            ["Schedule.Service", "ITaskService", "TaskScheduler"]),

        new("Shell Command Execution",
            "cmd.exe /c invocation found — binary executes OS shell commands.",
            Severity.Suspicious, DetectionCategory.Injection,
            ["cmd.exe /c", "cmd /c ", "cmd.exe /k"]),

        new("PowerShell Invocation",
            "PowerShell process name found in strings — may run scripts or download payloads.",
            Severity.Suspicious, DetectionCategory.Injection,
            ["powershell", "powershell.exe", "pwsh.exe"]),

        new("PowerShell Download Cradle",
            "PowerShell DownloadString/IEX pattern — classic fileless malware loader.",
            Severity.Dangerous, DetectionCategory.Injection,
            ["DownloadString", "IEX(", "Invoke-Expression", "IEX (New-Object"]),

        new("WScript / CScript Execution",
            "WScript.Shell or Shell.Application COM object found — binary may run scripts via Windows Scripting Host.",
            Severity.Suspicious, DetectionCategory.Injection,
            ["WScript.Shell", "Shell.Application", "CScript.exe"], IgnoreCase: false),

        new("Base64-Encoded PE Dropper",
            "Base64-encoded MZ/PE header detected — binary may decode and execute another executable in memory.",
            Severity.Dangerous, DetectionCategory.Packing,
            ["TVqQAAMAAAAEAAAA", "TVpQAAIAAAAEAA=="], IgnoreCase: false),

        new("Cobalt Strike / Beacon",
            "Cobalt Strike beacon or loader markers detected.",
            Severity.Dangerous, DetectionCategory.Injection,
            ["cobaltstrike", "beacon", "ReflectiveLoader"]),

        new("Common Malware Drop Paths",
            "AppData/Temp file paths typically used by malware to drop and persist payloads.",
            Severity.Suspicious, DetectionCategory.Persistence,
            ["\\AppData\\Roaming\\", "\\AppData\\Local\\Temp\\", "%TEMP%\\", "%APPDATA%\\"],
            IgnoreCase: false),

        new("Shadow Copy Deletion",
            "Volume Shadow Copy deletion command found — hallmark ransomware behavior to prevent recovery.",
            Severity.Dangerous, DetectionCategory.Ransomware,
            ["vssadmin delete shadows", "wmic shadowcopy delete", "bcdedit /set {default}"]),

        new("Ransomware Strings",
            "Strings associated with ransomware extortion behavior.",
            Severity.Dangerous, DetectionCategory.Ransomware,
            ["YOUR_FILES_ARE_ENCRYPTED", "HOW_TO_DECRYPT", ".locked", ".encrypted", "README_FOR_DECRYPT"]),

        new("Anti-Sandbox / Anti-VM Strings",
            "Known VM/sandbox process or DLL names found — binary checks its execution environment.",
            Severity.Suspicious, DetectionCategory.Evasion,
            ["SbieDll.dll", "vmtoolsd.exe", "vboxservice.exe", "VirtualBox", "VMWARE", "Sandboxie"]),

        new("Tor / Onion C2",
            ".onion address found — binary may communicate through the Tor anonymisation network.",
            Severity.Dangerous, DetectionCategory.Network,
            [".onion", "torproject.org"]),

        new("Crypto-Mining",
            "Stratum mining protocol or XMR/Monero strings found — possible crypto-miner payload.",
            Severity.Dangerous, DetectionCategory.Crypto,
            ["stratum+tcp://", "xmrig", "cryptonight", "monero"]),
    ];

    // ── Public scan entry point ───────────────────────────────────────────────

    private const int MaxScanBytes = 10 * 1024 * 1024;

    public IEnumerable<Detection> Scan(string filePath)
    {
        byte[] raw;
        try
        {
            using var fs = File.OpenRead(filePath);
            raw = new byte[Math.Min(fs.Length, MaxScanBytes)];
            fs.ReadExactly(raw);
        }
        catch { yield break; }

        // Built-in byte rules (skip first 64 bytes for embedded PE check)
        foreach (var rule in BuiltinByteRules)
        {
            var span = rule.Name == "Embedded PE (MZ Header)"
                ? raw.AsSpan(64)
                : raw.AsSpan();
            if (ContainsBytes(span, rule.Pattern))
                yield return new Detection(rule.Name, rule.Description, rule.Severity, rule.Category);
        }

        // Built-in string rules
        string ascii = ToAsciiBlob(raw);
        foreach (var rule in BuiltinStringRules)
        {
            var cmp = rule.IgnoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            if (rule.Patterns.Any(p => ascii.Contains(p, cmp)))
                yield return new Detection(rule.Name, rule.Description, rule.Severity, rule.Category);
        }

        // Custom YARA rules from folder
        foreach (var rule in _customRules)
        {
            if (EvaluateYaraRule(rule, raw, ascii))
                yield return new Detection(
                    $"YARA: {rule.Name}",
                    rule.Description.Length > 0
                        ? rule.Description
                        : $"Custom YARA rule '{rule.Name}' matched.",
                    rule.Severity,
                    DetectionCategory.Yara);
        }
    }

    // ── YARA rule parsing ─────────────────────────────────────────────────────

    private sealed class ParsedYaraRule
    {
        public string Name        { get; init; } = "";
        public string Description { get; init; } = "";
        public Severity Severity  { get; init; } = Severity.Suspicious;
        public Dictionary<string, YaraPattern> Strings { get; init; } = [];
        public string Condition   { get; init; } = "";
    }

    private abstract record YaraPattern;
    private sealed record LiteralPattern(string Text, bool NoCase) : YaraPattern;
    private sealed record HexPattern(byte?[] Bytes) : YaraPattern;   // null = wildcard

    private static readonly Regex RuleRegex = new(
        @"(?:\/\/\s*severity\s*:\s*(\w+)\s*\n)?" +
        @"rule\s+(\w+)\s*\{" +
        @"(?:.*?meta:\s*(.*?))?" +
        @"(?:.*?strings:\s*(.*?))?" +
        @"condition:\s*(.*?)" +
        @"\}",
        RegexOptions.Singleline | RegexOptions.IgnoreCase);

    private static readonly Regex StringDefRegex = new(
        @"\$(\w+)\s*=\s*(?:""([^""]*)""\s*(nocase)?|\{\s*([0-9A-Fa-f\s?]+)\s*\})",
        RegexOptions.IgnoreCase);

    private static readonly Regex MetaDescRegex = new(
        @"description\s*=\s*""([^""]*)""",
        RegexOptions.IgnoreCase);

    private static IEnumerable<ParsedYaraRule> ParseRuleFile(string path)
    {
        string text;
        try { text = File.ReadAllText(path); }
        catch { yield break; }

        foreach (Match m in RuleRegex.Matches(text))
        {
            var severityStr = m.Groups[1].Value.Trim().ToLowerInvariant();
            var severity = severityStr switch
            {
                "dangerous" or "high" or "critical" => Severity.Dangerous,
                "safe" or "info" or "low"            => Severity.Safe,
                _                                    => Severity.Suspicious
            };

            string ruleName  = m.Groups[2].Value.Trim();
            string metaSec   = m.Groups[3].Value;
            string stringSec = m.Groups[4].Value;
            string condition = m.Groups[5].Value.Trim().ToLowerInvariant();

            string desc = MetaDescRegex.Match(metaSec) is { Success: true } dm
                ? dm.Groups[1].Value
                : "";

            var patterns = new Dictionary<string, YaraPattern>(StringComparer.OrdinalIgnoreCase);
            foreach (Match sm in StringDefRegex.Matches(stringSec))
            {
                string varName = sm.Groups[1].Value;
                if (sm.Groups[2].Success)
                {
                    // literal string
                    bool noCase = sm.Groups[3].Success;
                    patterns[$"${varName}"] = new LiteralPattern(sm.Groups[2].Value, noCase);
                }
                else if (sm.Groups[4].Success)
                {
                    // hex pattern
                    patterns[$"${varName}"] = ParseHexPattern(sm.Groups[4].Value);
                }
            }

            yield return new ParsedYaraRule
            {
                Name        = ruleName,
                Description = desc,
                Severity    = severity,
                Strings     = patterns,
                Condition   = condition,
            };
        }
    }

    private static HexPattern ParseHexPattern(string hex)
    {
        var tokens = hex.Trim().Split([' ', '\t', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries);
        var bytes  = new List<byte?>();
        foreach (var t in tokens)
        {
            if (t == "??" || t == "?")
                bytes.Add(null);
            else if (byte.TryParse(t, System.Globalization.NumberStyles.HexNumber, null, out byte b))
                bytes.Add(b);
        }
        return new HexPattern(bytes.ToArray());
    }

    // ── YARA condition evaluator ──────────────────────────────────────────────

    private static bool EvaluateYaraRule(ParsedYaraRule rule, byte[] raw, string ascii)
    {
        if (rule.Strings.Count == 0) return false;

        // Cache which pattern vars matched
        var matched = rule.Strings.ToDictionary(
            kvp => kvp.Key,
            kvp => PatternMatches(kvp.Value, raw, ascii),
            StringComparer.OrdinalIgnoreCase);

        return EvaluateCondition(rule.Condition, matched);
    }

    private static bool EvaluateCondition(string cond, Dictionary<string, bool> matched)
    {
        cond = cond.Trim().TrimEnd('}').Trim();

        if (cond == "any of them") return matched.Values.Any(v => v);
        if (cond == "all of them") return matched.Values.All(v => v);

        // Tokenised evaluation of: $a, not $a, $a and $b, $a or $b
        var tokens = cond.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
        return EvalTokens(tokens, 0, matched, out _);
    }

    private static bool EvalTokens(string[] toks, int i,
        Dictionary<string, bool> matched, out int consumed)
    {
        consumed = 0;
        if (i >= toks.Length) return false;

        bool negate = false;
        if (toks[i].Equals("not", StringComparison.OrdinalIgnoreCase)) { negate = true; i++; consumed++; }

        bool left;
        if (toks[i].StartsWith('$'))
        {
            left = matched.TryGetValue(toks[i], out bool v) && v;
            consumed++;
            i++;
        }
        else { consumed = 0; return false; }

        if (negate) left = !left;

        while (i < toks.Length)
        {
            string op = toks[i].ToLowerInvariant();
            if (op != "and" && op != "or") break;
            i++; consumed++;

            bool rightNegate = false;
            if (i < toks.Length && toks[i].Equals("not", StringComparison.OrdinalIgnoreCase))
            { rightNegate = true; i++; consumed++; }

            if (i >= toks.Length || !toks[i].StartsWith('$')) break;
            bool right = matched.TryGetValue(toks[i], out bool rv) && rv;
            if (rightNegate) right = !right;
            i++; consumed++;

            left = op == "and" ? left && right : left || right;
        }

        return left;
    }

    private static bool PatternMatches(YaraPattern pattern, byte[] raw, string ascii)
        => pattern switch
        {
            LiteralPattern lp => ascii.Contains(lp.Text,
                lp.NoCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal),
            HexPattern hp => ContainsWildcardBytes(raw.AsSpan(), hp.Bytes),
            _             => false
        };

    // ── Low-level helpers ─────────────────────────────────────────────────────

    private static bool ContainsBytes(ReadOnlySpan<byte> hay, byte[] needle)
        => needle.Length > 0 && hay.Length >= needle.Length
           && hay.IndexOf(needle.AsSpan()) >= 0;

    private static bool ContainsWildcardBytes(ReadOnlySpan<byte> hay, byte?[] pat)
    {
        if (pat.Length == 0 || hay.Length < pat.Length) return false;
        for (int i = 0; i <= hay.Length - pat.Length; i++)
        {
            bool ok = true;
            for (int j = 0; j < pat.Length; j++)
            {
                if (pat[j].HasValue && hay[i + j] != pat[j]!.Value) { ok = false; break; }
            }
            if (ok) return true;
        }
        return false;
    }

    private static string ToAsciiBlob(byte[] raw)
    {
        var sb = new StringBuilder(raw.Length);
        foreach (byte b in raw)
            sb.Append(b >= 0x20 && b < 0x7F ? (char)b : ' ');
        return sb.ToString();
    }
}
