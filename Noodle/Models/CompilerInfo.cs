namespace Noodle.Core.Models;

public sealed record CompilerInfo(
    string Language,
    string Compiler,
    string Runtime,
    string LinkerVersion,
    IReadOnlyList<string> Hints
);
