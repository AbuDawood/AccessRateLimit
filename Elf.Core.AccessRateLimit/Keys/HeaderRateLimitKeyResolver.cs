using Microsoft.AspNetCore.Http;

namespace Elf.Core.AccessRateLimit;

/// <summary>
/// Resolves a key from a single HTTP header.
/// </summary>
public sealed class HeaderRateLimitKeyResolver : IRateLimitKeyResolver
{
    private readonly string _headerName;

    /// <summary>
    /// Creates a resolver for the specified header name.
    /// </summary>
    public HeaderRateLimitKeyResolver(string headerName)
    {
        if (string.IsNullOrWhiteSpace(headerName))
        {
            throw new ArgumentException("Header name is required.", nameof(headerName));
        }

        _headerName = headerName;
    }

    /// <summary>
    /// Resolves the first header value when present.
    /// </summary>
    public ValueTask<string?> ResolveAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        if (!context.Request.Headers.TryGetValue(_headerName, out var values))
        {
            return new ValueTask<string?>((string?)null);
        }

        var value = values.Count > 0 ? values[0] : null;
        return new ValueTask<string?>(value);
    }
}
