using System.Text;
using System.Text.RegularExpressions;
using Noodle.Core.Models;

namespace Noodle.Core.Services;

public sealed class YaraScanner
{
    private static readonly string RulesDir =
        Path.Combine(AppContext.BaseDirectory, "YaraRules");

    public int RuleFileCount { get; }
    private readonly IReadOnlyList<ParsedYaraRule> _customRules;

    public YaraScanner()
    {
        string[] yarFiles = [];
        string[] yaraFiles = [];
        string[] allFiles = [];

        EnsureRulesFolder();

        yarFiles = Directory.GetFiles(RulesDir, "*.yar", SearchOption.AllDirectories);
        yaraFiles = Directory.GetFiles(RulesDir, "*.yara", SearchOption.AllDirectories);
        allFiles = yarFiles.Concat(yaraFiles).ToArray();

        RuleFileCount = allFiles.Length;
        _customRules = allFiles.SelectMany(ParseRuleFile).ToList();
    }

    private sealed class ParsedYaraRule
    {
        public string Name { get; init; } = "";
        public string Description { get; init; } = "";
        public Severity Severity { get; init; } = Severity.Suspicious;
        public Dictionary<string, YaraString> Strings { get; init; } = [];
        public string Condition { get; init; } = "";
    }

    private abstract record YaraString;

    private sealed record LiteralString(
        string Text,
        bool NoCase,
        bool Wide,
        bool HasAscii,
        bool FullWord) : YaraString;

    private sealed record HexString(byte?[] Bytes) : YaraString;

    private const int MaxScanBytes = 10 * 1024 * 1024;

    public IEnumerable<Detection> Scan(string filePath)
    {
        return Enumerable.Empty<Detection>();
    }

    public IReadOnlyList<YaraRuleResult> ScanCustomRules(
        string filePath,
        Action<string, int, int>? onRule = null)
    {
        if (_customRules.Count == 0) return [];
        if (!File.Exists(filePath)) return [];

        FileStream fs = File.OpenRead(filePath);
        int byteCount = (int)Math.Min(fs.Length, MaxScanBytes);
        byte[] raw = new byte[byteCount];
        byte[] rawLower = new byte[byteCount];
        YaraRuleResult[] results = new YaraRuleResult[_customRules.Count];
        int total = _customRules.Count;
        int done = 0;

        fs.ReadExactly(raw);
        fs.Dispose();

        for (int k = 0; k < byteCount; k++)
        {
            byte b = raw[k];
            rawLower[k] = (b >= 65 && b <= 90) ? (byte)(b + 32) : b;
        }

        ParallelOptions opts = new ParallelOptions
        {
            MaxDegreeOfParallelism = Math.Max(1, Environment.ProcessorCount / 2)
        };

        Parallel.For(0, total, opts, i =>
        {
            ParsedYaraRule rule = _customRules[i];
            bool matched = EvaluateRule(rule, raw, rawLower);
            string desc = rule.Description.Length > 0
                ? rule.Description
                : $"Custom YARA rule '{rule.Name}'";
            int current = Interlocked.Increment(ref done);

            results[i] = new YaraRuleResult(rule.Name, desc, rule.Severity, matched);
            onRule?.Invoke(rule.Name, current, total);
        });

        return results;
    }

    private static void EnsureRulesFolder()
    {
        if (Directory.Exists(RulesDir)) return;

        Directory.CreateDirectory(RulesDir);
    }

    private static readonly Regex RxSeverityComment = new(
        @"//\s*severity\s*:\s*(\w+)\s*$",
        RegexOptions.Multiline | RegexOptions.IgnoreCase);

    private static readonly Regex RxRuleHeader = new(
        @"rule\s+(\w+)(?:\s*:[^{]*)?\s*\{",
        RegexOptions.IgnoreCase);

    private static readonly Regex RxLiteralDef = new(
        @"^\s*\$(\w+)\s*=\s*""((?:[^""\r\n\\]|\\[^\r\n])*)""\s*((?:(?:nocase|wide|ascii|fullword)[ \t]*)*)",
        RegexOptions.Multiline | RegexOptions.IgnoreCase);

    private static readonly Regex RxHexDef = new(
        @"^\s*\$(\w+)\s*=\s*\{([^}]*)\}",
        RegexOptions.Multiline | RegexOptions.Singleline | RegexOptions.IgnoreCase);

    private static readonly Regex RxMetaDesc = new(
        @"description\s*=\s*""([^""]*)""",
        RegexOptions.IgnoreCase);

    private static readonly Regex RxSectionHeader = new(
        @"^\s*(meta|strings|condition)\s*:",
        RegexOptions.Multiline | RegexOptions.IgnoreCase);

    private static IEnumerable<ParsedYaraRule> ParseRuleFile(string path)
    {
        string text = "";
        int pos = 0;
        Match headerMatch = Match.Empty;

        if (!File.Exists(path)) yield break;

        text = File.ReadAllText(path);
        headerMatch = RxRuleHeader.Match(text, pos);

        while (pos < text.Length && headerMatch.Success)
        {
            string ruleName = headerMatch.Groups[1].Value;
            string before = text[pos..headerMatch.Index];
            Severity severity = Severity.Suspicious;
            Match sevMatch = RxSeverityComment.Match(before);
            int braceOpen = headerMatch.Index + headerMatch.Length - 1;
            int braceClose = FindMatchingBrace(text, braceOpen);
            string body = "";
            ParsedYaraRule? rule = null;

            if (sevMatch.Success)
            {
                severity = sevMatch.Groups[1].Value.ToLowerInvariant() switch
                {
                    "dangerous" or "high" or "critical" => Severity.Dangerous,
                    "safe" or "info" or "low" => Severity.Safe,
                    _ => Severity.Suspicious
                };
            }

            if (braceClose < 0)
            {
                pos = headerMatch.Index + headerMatch.Length;
                headerMatch = RxRuleHeader.Match(text, pos);
                continue;
            }

            body = text[(braceOpen + 1)..braceClose];
            rule = ParseRuleBody(ruleName, severity, body);

            if (rule != null) yield return rule;

            pos = braceClose + 1;
            headerMatch = RxRuleHeader.Match(text, pos);
        }
    }

    private static int FindMatchingBrace(string text, int openIdx)
    {
        int depth = 0;
        bool inLineComment = false;
        bool inString = false;
        int i = openIdx;

        while (i < text.Length)
        {
            char c = text[i];

            if (!inString && !inLineComment && i + 1 < text.Length && c == '/' && text[i + 1] == '/')
            {
                inLineComment = true;
                i = i + 2;
                continue;
            }

            if (inLineComment)
            {
                inLineComment = c != '\n';
                i = i + 1;
                continue;
            }

            if (c == '"' && !inString) { inString = true; i = i + 1; continue; }
            if (c == '"' && inString) { inString = false; i = i + 1; continue; }
            if (inString) { i = i + 1; continue; }

            if (c == '{') depth = depth + 1;
            if (c == '}')
            {
                depth = depth - 1;
                if (depth == 0) return i;
            }

            i = i + 1;
        }

        return -1;
    }

    private static ParsedYaraRule? ParseRuleBody(string name, Severity severity, string body)
    {
        string metaSection = ExtractSection(body, "meta");
        string stringsSection = ExtractSection(body, "strings");
        string conditionSection = ExtractSection(body, "condition");
        string desc = "";
        Match descMatch = RxMetaDesc.Match(metaSection);
        Dictionary<string, YaraString> patterns = new Dictionary<string, YaraString>(
            StringComparer.OrdinalIgnoreCase);

        if (conditionSection.Length == 0) return null;

        if (descMatch.Success) desc = descMatch.Groups[1].Value;

        foreach (Match lm in RxLiteralDef.Matches(stringsSection))
        {
            string varName = lm.Groups[1].Value;
            string rawText = lm.Groups[2].Value;
            string mods = lm.Groups[3].Value.ToLowerInvariant();
            string unescaped = UnescapeString(rawText);
            bool noCase = mods.Contains("nocase");
            bool wide = mods.Contains("wide");
            bool hasAscii = mods.Contains("ascii");
            bool fullWord = mods.Contains("fullword");

            patterns[$"${varName}"] = new LiteralString(unescaped, noCase, wide, hasAscii, fullWord);
        }

        foreach (Match hm in RxHexDef.Matches(stringsSection))
        {
            string varName = hm.Groups[1].Value;
            string hexBody = hm.Groups[2].Value;

            if (!patterns.ContainsKey($"${varName}"))
            {
                patterns[$"${varName}"] = ParseHexString(hexBody);
            }
        }

        return new ParsedYaraRule
        {
            Name = name,
            Description = desc,
            Severity = severity,
            Strings = patterns,
            Condition = conditionSection.Trim(),
        };
    }

    private static string ExtractSection(string body, string sectionName)
    {
        MatchCollection matches = RxSectionHeader.Matches(body);
        string result = "";
        int idx = 0;

        while (idx < matches.Count && result.Length == 0)
        {
            if (matches[idx].Groups[1].Value.Equals(sectionName, StringComparison.OrdinalIgnoreCase))
            {
                int start = matches[idx].Index + matches[idx].Length;
                int end = idx + 1 < matches.Count ? matches[idx + 1].Index : body.Length;

                result = body[start..end];
            }

            idx = idx + 1;
        }

        return result;
    }

    private static string UnescapeString(string s)
    {
        StringBuilder sb = new StringBuilder(s.Length);
        int i = 0;
        bool isEscape = false;
        char next = '\0';

        while (i < s.Length)
        {
            isEscape = s[i] == '\\' && i + 1 < s.Length;

            if (!isEscape)
            {
                sb.Append(s[i]);
                i = i + 1;
                continue;
            }

            next = s[i + 1];

            if (next == 'x' && i + 3 < s.Length && IsHexChar(s[i + 2]) && IsHexChar(s[i + 3]))
            {
                sb.Append((char)Convert.ToByte(s.Substring(i + 2, 2), 16));
                i = i + 4;
                continue;
            }

            sb.Append(next switch
            {
                't' => '\t',
                'n' => '\n',
                'r' => '\r',
                '\\' => '\\',
                '"' => '"',
                _ => next
            });

            i = i + 2;
        }

        return sb.ToString();
    }

    private static bool IsHexChar(char c)
    {
        return (c >= '0' && c <= '9')
            || (c >= 'a' && c <= 'f')
            || (c >= 'A' && c <= 'F');
    }

    private static HexString ParseHexString(string hex)
    {
        string cleaned = Regex.Replace(hex, @"/\*.*?\*/", " ", RegexOptions.Singleline);
        List<byte?> bytes = new List<byte?>();
        string[] tokens = cleaned.Trim().Split(
            [' ', '\t', '\n', '\r'],
            StringSplitOptions.RemoveEmptyEntries);

        foreach (string t in tokens)
        {
            if (t == "??" || t == "?")
            {
                bytes.Add(null);
            }
            else if (t.StartsWith('[') && t.EndsWith(']'))
            {
                string inner = t[1..^1];
                int dashPos = inner.IndexOf('-');
                int minJump = 0;

                if (dashPos >= 0)
                {
                    int.TryParse(inner[..dashPos], out minJump);
                }
                else
                {
                    int.TryParse(inner, out minJump);
                }

                for (int k = 0; k < minJump; k++) bytes.Add(null);
            }
            else if (t.Length == 2
                && byte.TryParse(t, System.Globalization.NumberStyles.HexNumber, null, out byte b))
            {
                bytes.Add(b);
            }
        }

        return new HexString(bytes.ToArray());
    }

    private static bool EvaluateRule(ParsedYaraRule rule, byte[] raw, byte[] rawLower)
    {
        Dictionary<string, bool> hits = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

        foreach (KeyValuePair<string, YaraString> kv in rule.Strings)
        {
            hits[kv.Key] = PatternMatches(kv.Value, raw, rawLower);
        }

        return EvaluateCondition(rule.Condition, hits);
    }

    private static bool EvaluateCondition(string cond, Dictionary<string, bool> hits)
    {
        string normalized = Regex.Replace(cond.Trim(), @"\s+", " ");
        string lower = normalized.ToLowerInvariant();
        Match countMatch = Match.Empty;
        Match ofGroup = Match.Empty;

        if (lower == "any of them")
        {
            return hits.Count > 0 && hits.Values.Any(v => v);
        }

        if (lower == "all of them")
        {
            return hits.Count > 0 && hits.Values.All(v => v);
        }

        countMatch = Regex.Match(normalized, @"^(\d+)\s+of\s+them$", RegexOptions.IgnoreCase);

        if (countMatch.Success)
        {
            int needed = int.Parse(countMatch.Groups[1].Value);
            return hits.Values.Count(v => v) >= needed;
        }

        ofGroup = Regex.Match(
            normalized,
            @"^(any|all)\s+of\s+\(([^)]+)\)$",
            RegexOptions.IgnoreCase);

        if (ofGroup.Success)
        {
            bool wantAll = ofGroup.Groups[1].Value.Equals("all", StringComparison.OrdinalIgnoreCase);
            bool[] vals = ResolveVarList(ofGroup.Groups[2].Value, hits);

            return wantAll ? vals.All(v => v) : vals.Any(v => v);
        }

        string[] tokens = normalized.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);

        return EvalTokens(tokens, 0, hits);
    }

    private static bool[] ResolveVarList(string inner, Dictionary<string, bool> hits)
    {
        string[] parts = inner.Split(',');
        List<bool> results = new List<bool>();

        foreach (string part in parts)
        {
            string name = part.Trim();

            if (name.EndsWith('*'))
            {
                string prefix = name[..^1];

                foreach (KeyValuePair<string, bool> kv in hits)
                {
                    if (kv.Key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    {
                        results.Add(kv.Value);
                    }
                }
            }
            else if (name.StartsWith('$'))
            {
                results.Add(hits.TryGetValue(name, out bool v) && v);
            }
        }

        return results.ToArray();
    }

    private static bool EvalTokens(string[] toks, int start, Dictionary<string, bool> hits)
    {
        int i = start;
        bool negate = false;
        bool left = false;
        string op = "";

        if (i >= toks.Length) return false;

        if (toks[i].Equals("not", StringComparison.OrdinalIgnoreCase))
        {
            negate = true;
            i = i + 1;
        }

        if (i >= toks.Length || !toks[i].StartsWith('$')) return false;

        left = hits.TryGetValue(toks[i], out bool lv) && lv;
        i = i + 1;

        if (negate) left = !left;

        op = i < toks.Length ? toks[i].ToLowerInvariant() : "";

        while (i < toks.Length && (op == "and" || op == "or"))
        {
            bool rightNegate = false;
            bool rightUnknown = false;
            bool right = false;

            i = i + 1;

            if (i < toks.Length && toks[i].Equals("not", StringComparison.OrdinalIgnoreCase))
            {
                rightNegate = true;
                i = i + 1;
            }

            if (i >= toks.Length || !toks[i].StartsWith('$'))
            {
                rightUnknown = true;
            }

            if (rightUnknown)
            {
                if (op == "and") return false;

                op = "";
            }
            else
            {
                right = hits.TryGetValue(toks[i], out bool rv) && rv;

                if (rightNegate) right = !right;

                i = i + 1;
                left = op == "and" ? left && right : left || right;
                op = i < toks.Length ? toks[i].ToLowerInvariant() : "";
            }
        }

        return left;
    }

    private static bool PatternMatches(YaraString pattern, byte[] raw, byte[] rawLower)
    {
        bool wantAscii = false;
        bool wantWide = false;
        bool result = false;

        if (pattern is LiteralString ls)
        {
            wantAscii = ls.HasAscii || !ls.Wide;
            wantWide = ls.Wide;

            if (wantAscii && !result)
            {
                byte[] needle = Encoding.ASCII.GetBytes(ls.Text);

                result = ls.FullWord
                    ? ContainsFullWordBytes(raw, rawLower, needle, ls.NoCase)
                    : ContainsBytesNC(raw, rawLower, needle, ls.NoCase);
            }

            if (wantWide && !result)
            {
                byte[] wideBytes = Encoding.Unicode.GetBytes(ls.Text);
                result = ContainsBytes(raw.AsSpan(), wideBytes);
            }
        }
        else if (pattern is HexString hs)
        {
            result = ContainsWildcardBytes(raw.AsSpan(), hs.Bytes);
        }

        return result;
    }

    private static bool ContainsBytesNC(byte[] raw, byte[] rawLower, byte[] needle, bool noCase)
    {
        if (needle.Length == 0 || raw.Length < needle.Length) return false;

        if (!noCase) return raw.AsSpan().IndexOf(needle.AsSpan()) >= 0;

        byte[] needleLower = LowerBytes(needle);

        return rawLower.AsSpan().IndexOf(needleLower.AsSpan()) >= 0;
    }

    private static bool ContainsFullWordBytes(byte[] raw, byte[] rawLower, byte[] needle, bool noCase)
    {
        if (needle.Length == 0 || raw.Length < needle.Length) return false;

        byte[] search = noCase ? LowerBytes(needle) : needle;
        ReadOnlySpan<byte> haystack = noCase ? rawLower.AsSpan() : raw.AsSpan();
        int offset = 0;
        bool matched = false;

        while (!matched)
        {
            int idx = haystack.Slice(offset).IndexOf(search.AsSpan());

            if (idx < 0) break;

            int abs = offset + idx;
            bool before = abs == 0 || !IsWordByte(raw[abs - 1]);
            bool after = abs + needle.Length >= raw.Length || !IsWordByte(raw[abs + needle.Length]);

            if (before && after) matched = true;

            offset = abs + 1;
        }

        return matched;
    }

    private static byte[] LowerBytes(byte[] src)
    {
        byte[] dst = new byte[src.Length];

        for (int i = 0; i < src.Length; i++)
        {
            byte b = src[i];
            dst[i] = (b >= 65 && b <= 90) ? (byte)(b + 32) : b;
        }

        return dst;
    }

    private static bool IsWordByte(byte b)
    {
        return (b >= (byte)'a' && b <= (byte)'z')
            || (b >= (byte)'A' && b <= (byte)'Z')
            || (b >= (byte)'0' && b <= (byte)'9')
            || b == (byte)'_';
    }

    private static bool ContainsBytes(ReadOnlySpan<byte> haystack, byte[] needle)
    {
        if (needle.Length == 0 || haystack.Length < needle.Length) return false;
        return haystack.IndexOf(needle.AsSpan()) >= 0;
    }

    private static bool ContainsWildcardBytes(ReadOnlySpan<byte> haystack, byte?[] pattern)
    {
        int limit = haystack.Length - pattern.Length;
        bool found = false;
        int i = 0;

        if (pattern.Length == 0 || haystack.Length < pattern.Length) return false;

        while (i <= limit && !found)
        {
            bool ok = true;
            int j = 0;

            while (j < pattern.Length && ok)
            {
                if (pattern[j].HasValue && haystack[i + j] != pattern[j]!.Value)
                {
                    ok = false;
                }

                j = j + 1;
            }

            if (ok) found = true;

            i = i + 1;
        }

        return found;
    }
}
