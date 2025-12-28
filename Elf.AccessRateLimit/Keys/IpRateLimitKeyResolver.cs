using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace Elf.AccessRateLimit;

/// <summary>
/// Resolves the caller IP address from forwarded headers or the connection.
/// </summary>
public sealed class IpRateLimitKeyResolver : IRateLimitKeyResolver
{
    private static readonly string[] DefaultForwardedHeaders = { "X-Forwarded-For", "X-Real-IP" };
    private readonly bool _preferForwardedHeaders;
    private readonly IReadOnlyList<string> _forwardedHeaderNames;

    /// <summary>
    /// Uses forwarded headers with a fallback to the remote IP.
    /// </summary>
    public IpRateLimitKeyResolver()
        : this(preferForwardedHeaders: true, DefaultForwardedHeaders)
    {
    }

    /// <summary>
    /// Creates a resolver with custom forwarded header settings.
    /// </summary>
    public IpRateLimitKeyResolver(bool preferForwardedHeaders, params string[] forwardedHeaderNames)
    {
        _preferForwardedHeaders = preferForwardedHeaders;
        _forwardedHeaderNames = forwardedHeaderNames is { Length: > 0 }
            ? forwardedHeaderNames
            : DefaultForwardedHeaders;
    }

    /// <summary>
    /// Resolves the IP address for the current request.
    /// </summary>
    public ValueTask<string?> ResolveAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        // Prefer forwarded headers when behind proxies like Ocelot.
        if (_preferForwardedHeaders)
        {
            var forwardedIp = TryGetForwardedIp(context);
            if (!string.IsNullOrWhiteSpace(forwardedIp))
            {
                return new ValueTask<string?>(forwardedIp);
            }
        }

        return new ValueTask<string?>(context.Connection.RemoteIpAddress?.ToString());
    }

    private string? TryGetForwardedIp(HttpContext context)
    {
        foreach (var headerName in _forwardedHeaderNames)
        {
            if (context.Request.Headers.TryGetValue(headerName, out var values))
            {
                var candidate = ParseForwardedHeader(values);
                if (!string.IsNullOrWhiteSpace(candidate))
                {
                    return candidate;
                }
            }
        }

        return null;
    }

    private static string? ParseForwardedHeader(StringValues values)
    {
        foreach (var raw in values)
        {
            if (string.IsNullOrWhiteSpace(raw))
            {
                continue;
            }

            var parts = raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            foreach (var part in parts)
            {
                if (TryNormalizeIp(part, out var ip))
                {
                    return ip;
                }
            }
        }

        return null;
    }

    private static bool TryNormalizeIp(string value, out string? ip)
    {
        ip = null;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var candidate = value.Trim();

        if (candidate.StartsWith("[", StringComparison.Ordinal))
        {
            var endBracket = candidate.IndexOf(']');
            if (endBracket > 1)
            {
                candidate = candidate.Substring(1, endBracket - 1);
            }
        }

        if (IPAddress.TryParse(candidate, out var address))
        {
            ip = address.ToString();
            return true;
        }

        var colonIndex = candidate.LastIndexOf(':');
        if (colonIndex > 0 && candidate.Contains('.') && candidate.IndexOf(':') == colonIndex)
        {
            var withoutPort = candidate.Substring(0, colonIndex);
            if (IPAddress.TryParse(withoutPort, out address))
            {
                ip = address.ToString();
                return true;
            }
        }

        return false;
    }
}
