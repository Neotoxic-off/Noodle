namespace Noodle.Core.Models;

public sealed record FileMetadata(
    string FilePath,
    string FileName,
    long FileSize,
    string MD5,
    string SHA256,
    string FileType,
    string MagicBytes
);
