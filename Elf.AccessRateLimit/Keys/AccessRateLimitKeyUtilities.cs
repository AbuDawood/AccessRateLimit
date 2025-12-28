using System.Security.Cryptography;
using System.Text;

namespace Elf.AccessRateLimit;

internal static class AccessRateLimitKeyUtilities
{
    public static string Hash(string key)
    {
        var bytes = Encoding.UTF8.GetBytes(key);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash);
    }

    public static string Fingerprint(string hash)
    {
        if (string.IsNullOrWhiteSpace(hash))
        {
            return string.Empty;
        }

        return hash.Length <= 12 ? hash : hash.Substring(0, 12);
    }

    public static string NormalizeSegment(string? segment)
    {
        if (string.IsNullOrWhiteSpace(segment))
        {
            return "default";
        }

        var builder = new StringBuilder(segment.Length);
        foreach (var ch in segment)
        {
            if (ch <= 32 || ch == ':' || ch == '|' || ch == '/' || ch == '\\' || ch > 126)
            {
                builder.Append('_');
            }
            else
            {
                builder.Append(ch);
            }
        }

        return builder.ToString();
    }
}
