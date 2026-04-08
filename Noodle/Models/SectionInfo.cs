namespace Noodle.Core.Models;

public sealed record SectionInfo(
    string Name,
    double Entropy,
    uint VirtualAddress,
    uint VirtualSize,
    uint RawSize,
    uint PointerToRawData,
    bool IsExecutable,
    bool IsWritable
)
{
    public bool IsHighEntropy => Entropy >= 7.0;
    public bool IsPacked     => Entropy >= 7.2;
    public Severity EntropyLevel => Entropy switch
    {
        >= 7.2 => Severity.Dangerous,
        >= 6.5 => Severity.Suspicious,
        _      => Severity.Safe
    };
}
