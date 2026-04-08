using System.Security.Cryptography;

namespace Noodle.Core.Services;

public static class HashCalculator
{
    public static (string MD5, string SHA256) Compute(string path)
    {
        try
        {
            using var fs = File.OpenRead(path);
            var md5    = Convert.ToHexString(MD5.HashData(fs)).ToLower();
            fs.Seek(0, SeekOrigin.Begin);
            var sha256 = Convert.ToHexString(SHA256.HashData(fs)).ToLower();
            return (md5, sha256);
        }
        catch
        {
            return ("", "");
        }
    }
}
