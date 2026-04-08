using Noodle.Core.Models;

namespace Noodle.Core.Services;

public sealed class ImportAnalyzer
{
    private record Rule(string Name, string Description, Severity Severity, DetectionCategory Category, string[] Triggers);

    private static readonly Rule[] Rules =
    [
        new("Process Injection",
            "Imports functions commonly used for process injection (writing/executing code in foreign processes).",
            Severity.Dangerous, DetectionCategory.Injection,
            ["WriteProcessMemory","CreateRemoteThread","CreateRemoteThreadEx","NtCreateThread",
             "RtlCreateUserThread","QueueUserAPC","NtWriteVirtualMemory","ZwWriteVirtualMemory",
             "NtMapViewOfSection","ZwMapViewOfSection","SetThreadContext"]),

        new("Memory Manipulation",
            "Imports memory allocation functions in remote processes — often used to prepare injection targets.",
            Severity.Suspicious, DetectionCategory.Injection,
            ["VirtualAllocEx","VirtualProtectEx","OpenProcess","ReadProcessMemory"]),

        new("Anti-Debug",
            "Imports functions used to detect or evade debuggers.",
            Severity.Suspicious, DetectionCategory.AntiDebug,
            ["IsDebuggerPresent","CheckRemoteDebuggerPresent","NtQueryInformationProcess",
             "ZwQueryInformationProcess","OutputDebugStringA","OutputDebugStringW",
             "FindWindowA","FindWindowW","BlockInput"]),

        new("Network Activity",
            "Imports network functions — the binary may communicate over the internet.",
            Severity.Suspicious, DetectionCategory.Network,
            ["WSAStartup","WinHttpOpen","WinHttpSendRequest","InternetOpenA","InternetOpenW",
             "InternetOpenUrlA","InternetOpenUrlW","URLDownloadToFileA","URLDownloadToFileW",
             "HttpSendRequestA","HttpSendRequestW","socket","connect","send","recv",
             "getaddrinfo","gethostbyname","WSAConnect","FtpPutFileA","FtpGetFileA"]),

        new("Keylogger",
            "Imports functions used to capture keystrokes or monitor user input.",
            Severity.Dangerous, DetectionCategory.Keylogger,
            ["SetWindowsHookExA","SetWindowsHookExW","GetAsyncKeyState","GetKeyState",
             "RegisterHotKey","GetKeyboardState","MapVirtualKeyA","MapVirtualKeyW"]),

        new("Ransomware / Crypto",
            "Imports cryptographic functions — may be used for file encryption.",
            Severity.Suspicious, DetectionCategory.Crypto,
            ["CryptEncrypt","CryptDecrypt","CryptAcquireContextA","CryptAcquireContextW",
             "CryptCreateHash","BCryptEncrypt","BCryptDecrypt","BCryptOpenAlgorithmProvider",
             "BCryptGenerateKeyPair","CryptGenKey","CryptImportKey"]),

        new("Privilege Escalation",
            "Imports functions used to gain or manipulate Windows privileges and tokens.",
            Severity.Dangerous, DetectionCategory.Privilege,
            ["AdjustTokenPrivileges","ImpersonateLoggedOnUser","LookupPrivilegeValueA",
             "LookupPrivilegeValueW","OpenProcessToken","DuplicateTokenEx","SetTokenInformation"]),

        new("Screen Capture",
            "Imports functions used to capture the desktop or windows.",
            Severity.Suspicious, DetectionCategory.ScreenCapture,
            ["BitBlt","PrintWindow","GetDC","CreateCompatibleBitmap","CreateCompatibleDC"]),

        new("Service Manipulation",
            "Imports Service Control Manager functions — may install or manipulate Windows services.",
            Severity.Suspicious, DetectionCategory.Privilege,
            ["OpenSCManagerA","OpenSCManagerW","CreateServiceA","CreateServiceW",
             "StartServiceA","StartServiceW","ChangeServiceConfigA","ChangeServiceConfigW"]),

        new("Registry Persistence",
            "Imports registry functions used for common persistence mechanisms.",
            Severity.Suspicious, DetectionCategory.Anomaly,
            ["RegSetValueExA","RegSetValueExW","RegCreateKeyExA","RegCreateKeyExW",
             "RegOpenKeyExA","RegOpenKeyExW"]),

        new("Process Hollowing",
            "Combination of functions used in process hollowing attacks.",
            Severity.Dangerous, DetectionCategory.Injection,
            ["NtUnmapViewOfSection","ZwUnmapViewOfSection"]),

        new("Shellcode Execution",
            "Imports VirtualProtect which is frequently used to make shellcode executable.",
            Severity.Suspicious, DetectionCategory.Injection,
            ["VirtualProtect","VirtualAlloc"]),
    ];

    public IEnumerable<Detection> Analyze(IReadOnlyList<string> imports)
    {
        if (imports.Count == 0) yield break;

        var importSet = new HashSet<string>(imports, StringComparer.OrdinalIgnoreCase);

        foreach (var rule in Rules)
        {
            var triggered = rule.Triggers.Where(t => importSet.Contains(t)).ToList();
            if (triggered.Count == 0) continue;

            string detail = triggered.Count <= 3
                ? string.Join(", ", triggered)
                : $"{string.Join(", ", triggered.Take(3))} +{triggered.Count - 3} more";

            yield return new Detection(
                rule.Name,
                $"{rule.Description} Matched: {detail}.",
                rule.Severity,
                rule.Category
            );
        }
    }
}
