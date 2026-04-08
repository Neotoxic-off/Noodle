namespace Noodle.Core.Services;

public static class FileTypeDetector
{
    private static readonly (byte[] Magic, string Type)[] Signatures =
    [
        ([0x4D, 0x5A],                                  "PE/MZ Binary"),
        ([0x7F, 0x45, 0x4C, 0x46],                      "ELF Binary"),
        ([0xCA, 0xFE, 0xBA, 0xBE],                      "Mach-O Binary"),
        ([0x25, 0x50, 0x44, 0x46],                      "PDF Document"),
        ([0x50, 0x4B, 0x03, 0x04],                      "ZIP Archive"),
        ([0x50, 0x4B, 0x05, 0x06],                      "ZIP Archive (empty)"),
        ([0x52, 0x61, 0x72, 0x21],                      "RAR Archive"),
        ([0x1F, 0x8B],                                  "GZip Archive"),
        ([0x42, 0x5A, 0x68],                            "BZip2 Archive"),
        ([0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00],         "XZ Archive"),
        ([0xFF, 0xD8, 0xFF],                            "JPEG Image"),
        ([0x89, 0x50, 0x4E, 0x47],                      "PNG Image"),
        ([0x47, 0x49, 0x46, 0x38],                      "GIF Image"),
        ([0x49, 0x44, 0x33],                            "MP3 Audio"),
        ([0x52, 0x49, 0x46, 0x46],                      "RIFF (WAV/AVI)"),
        ([0x00, 0x00, 0x01, 0x00],                      "ICO Image"),
        ([0xD0, 0xCF, 0x11, 0xE0],                      "MS Office (Legacy)"),
        ([0x4D, 0x53, 0x43, 0x46],                      "MS Cabinet"),
        ([0x23, 0x21],                                  "Shell Script"),
        ([0x7B, 0x5C, 0x72, 0x74, 0x66],               "RTF Document"),
    ];

    public static (string Type, string MagicBytes) Detect(string path)
    {
        try
        {
            Span<byte> buf = stackalloc byte[16];
            using var fs = File.OpenRead(path);
            int read = fs.Read(buf);
            if (read == 0) return ("Empty File", "");

            var hex = Convert.ToHexString(buf[..Math.Min(read, 8)]);

            foreach (var (magic, type) in Signatures)
            {
                if (read >= magic.Length && buf[..magic.Length].SequenceEqual(magic))
                    return (type, hex);
            }

            bool isText = buf[..read].ToArray().All(b => b == 0x09 || b == 0x0A || b == 0x0D || (b >= 0x20 && b <= 0x7E));
            return (isText ? "Text File" : "Binary File", hex);
        }
        catch
        {
            return ("Unknown", "");
        }
    }
}
