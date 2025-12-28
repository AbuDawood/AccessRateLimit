using Microsoft.AspNetCore.Http;

namespace Elf.Core.AccessRateLimit;

/// <summary>
/// Resolves a key from a specific user claim.
/// </summary>
public sealed class ClaimRateLimitKeyResolver : IRateLimitKeyResolver
{
    private readonly string _claimType;

    /// <summary>
    /// Creates a resolver for the specified claim type.
    /// </summary>
    public ClaimRateLimitKeyResolver(string claimType)
    {
        if (string.IsNullOrWhiteSpace(claimType))
        {
            throw new ArgumentException("Claim type is required.", nameof(claimType));
        }

        _claimType = claimType;
    }

    /// <summary>
    /// Resolves the claim value for authenticated users.
    /// </summary>
    public ValueTask<string?> ResolveAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        if (context.User?.Identity?.IsAuthenticated != true)
        {
            return new ValueTask<string?>((string?)null);
        }

        var claim = context.User.FindFirst(_claimType);
        return new ValueTask<string?>(claim?.Value);
    }
}
