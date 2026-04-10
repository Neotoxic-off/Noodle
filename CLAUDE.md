# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build (use ~/.dotnet/dotnet — requires .NET 10 SDK)
~/.dotnet/dotnet build GUI/Noodle.App.csproj

# Run the GUI application (requires Windows — WPF is Windows-only)
~/.dotnet/dotnet run --project GUI/Noodle.App.csproj
```

The build is a single step: `GUI/Noodle.App.csproj` depends on `Noodle/Noodle.Core.csproj` and
builds it automatically. On Linux with `EnableWindowsTargeting`, the project uses a custom
`EnsureLibraryRef` MSBuild target to avoid a cross-compile race condition with WPF BAML compilation.

There are no test projects currently.

## Architecture

Noodle is a WPF desktop application for analyzing PE (Portable Executable) binary files.
It is split into two C# projects:

- **Noodle/** (`Noodle.Core.csproj`, `net10.0-windows`) — Core analysis library
- **GUI/** (`Noodle.App.csproj`, `net10.0-windows`) — WPF application; contains all UI code

The solution file is `Noodle.slnx` at the repo root (modern `.slnx` format, .NET 10 SDK only).

### Library layer (`Noodle/`)

Services (in `Services/`):
- `AnalysisService` — Orchestrates a full file analysis: file type detection, hashing, PE parsing,
  section analysis, import analysis, string extraction. Returns `AnalysisResult`.
- `PEAnalyzer` — Validates and parses PE files via PeNet. Extracts sections, imports, exports,
  entry point, TLS, debug info, overlay detection.
- `SectionAnalyzer` — Inspects sections for known packer names, high entropy, and RWX flags.
- `ImportAnalyzer` — Matches import tables against rule-based signatures (injection, keylogger, etc.).
- `StringExtractor` — Scans raw bytes for embedded URLs, IPs, and long Base64 blobs.
- `YaraScanner` — Stub (YaraSharp is .NET Framework only; disabled pending a modern replacement).
- `EntropyCalculator` / `HashCalculator` / `FileTypeDetector` — Utility helpers.

Models (in `Models/`): `AnalysisResult`, `Detection`, `DetectionCategory`, `FileMetadata`,
`PEInfo`, `SectionInfo`, `Severity`.

Key external dependencies: **PeNet** (PE parsing).

### GUI layer (`GUI/`)

Follows **MVVM** using `CommunityToolkit.Mvvm` source generators.

**Entry point:** `App.xaml.cs` — sets up Microsoft.Extensions.DependencyInjection, applies the
initial theme, and creates `MainWindow` with `ShellViewModel` as its DataContext.

**ViewModels** (in `ViewModels/`):
- `ShellViewModel` — Owns `CurrentPage` (object); swaps between Drop/Analysis/Settings via
  `GoHomeCommand` / `GoSettingsCommand` / `NavigateToAnalysis(result)`.
- `DropViewModel` — Manages the drag-and-drop landing page: `DropFileAsyncCommand`,
  `BrowseFileCommand`, `IsAnalyzing`, `StatusText`, `HasError`, `ErrorText`.
- `AnalysisViewModel` — Holds the `AnalysisResult`; exposes grouped detection collections
  (`DangerousDetections`, `SuspiciousDetections`, etc.) and `ScanAnotherCommand`.
- `SettingsViewModel` — `IsDarkTheme` toggle, which calls `ThemeManager.Instance.Apply()`.

**Views** (in `Views/`):
- `DropView` — Drag-and-drop zone (dashed Rectangle border), loading spinner, error panel.
- `AnalysisView` — Scrollable results: file metadata card, PE info card, detection cards
  grouped by severity, PE section table using `SectionBar` controls.
- `SettingsView` — Theme toggle switch + About info.

**Controls** (in `Controls/`):
- `DetectionTag` — Pill-shaped severity badge. `Label` (string) + `Severity` (object, bound
  to `Severity` enum at runtime). Brushes are resolved from theme resources.
- `SectionBar` — Horizontal bar showing section name, entropy fill bar, value, and X/W flags.

**Converters** (in `Converters/`): `BoolToVisibilityConverter`, `InverseBoolToVisibilityConverter`,
`InverseBoolConverter`, `SeverityToBrushConverter`, `SeverityToBgBrushConverter`,
`CategoryToIconConverter`, `FileSizeConverter`.

**Themes** (in `Themes/`): `Dark.xaml`, `Light.xaml` — resource dictionaries with color palette
and brush definitions. Swapped at runtime by `ThemeManager`.

**Styles** (in `Styles/Controls.xaml`): Typography, button styles (`Btn.Primary`, `Btn.Ghost`,
`Btn.Nav`, `Btn.Chrome`), `Card` border style, scrollbar, `ToggleSwitch` CheckBox style.

### Data flow

1. File dropped onto `DropView` → `DropFileAsyncCommand(path)` in `DropViewModel`
2. `IAnalysisService.AnalyzeAsync(path)` → `AnalysisService.Analyze()` runs all analyzers
3. Returns `AnalysisResult` → `ShellViewModel.NavigateToAnalysis(result)` → sets `CurrentPage`
4. `DataTemplate` in `App.xaml` maps `AnalysisViewModel` → `AnalysisView`

### Build notes

- `Noodle.Core.csproj` uses `ReferenceOutputAssembly=false` ProjectReference + a custom `EnsureLibraryRef`
  MSBuild target to work around a WPF BAML cross-compilation race condition on Linux.
- `YaraScanner` is a custom pure-.NET YARA-compatible engine (no native lib). String needles are
  pre-computed at startup. Scanning runs parallel with `ProcessorCount/4` threads at `BelowNormal`
  priority to avoid saturating the CPU.
