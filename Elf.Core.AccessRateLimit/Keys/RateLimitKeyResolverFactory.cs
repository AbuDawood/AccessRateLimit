using System.Security.Claims;

namespace Elf.Core.AccessRateLimit;

internal static class RateLimitKeyResolverFactory
{
    private static readonly IpRateLimitKeyResolver IpResolver = new();

    public static IRateLimitKeyResolver Create(AccessRateLimitPolicy policy, IRateLimitKeyResolver fallbackResolver)
    {
        if (policy.KeyResolver != null)
        {
            return policy.KeyResolver;
        }

        var specs = new List<string>();
        if (policy.KeyResolvers != null && policy.KeyResolvers.Count > 0)
        {
            specs.AddRange(policy.KeyResolvers);
        }

        if (!string.IsNullOrWhiteSpace(policy.KeyStrategy))
        {
            specs.AddRange(policy.KeyStrategy.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        }

        if (specs.Count == 0)
        {
            return fallbackResolver;
        }

        var resolvers = new List<IRateLimitKeyResolver>(specs.Count);
        foreach (var spec in specs)
        {
            resolvers.Add(Parse(spec));
        }

        return resolvers.Count == 1 ? resolvers[0] : new CompositeRateLimitKeyResolver(resolvers);
    }

    private static IRateLimitKeyResolver Parse(string spec)
    {
        if (string.IsNullOrWhiteSpace(spec))
        {
            throw new InvalidOperationException("Key resolver spec cannot be empty.");
        }

        var trimmed = spec.Trim();
        var lower = trimmed.ToLowerInvariant();
        if (lower == "ip")
        {
            return IpResolver;
        }

        if (lower == "user" || lower == "user-id")
        {
            return new ClaimRateLimitKeyResolver(ClaimTypes.NameIdentifier);
        }

        if (lower == "sub")
        {
            return new ClaimRateLimitKeyResolver("sub");
        }

        if (lower == "api-key")
        {
            return new HeaderRateLimitKeyResolver("X-Api-Key");
        }

        if (lower == "client-id")
        {
            return new HeaderRateLimitKeyResolver("X-Client-Id");
        }

        if (lower.StartsWith("claim:", StringComparison.Ordinal))
        {
            var claimType = trimmed.Substring("claim:".Length).Trim();
            return new ClaimRateLimitKeyResolver(claimType);
        }

        if (lower.StartsWith("header:", StringComparison.Ordinal))
        {
            var headerName = trimmed.Substring("header:".Length).Trim();
            return new HeaderRateLimitKeyResolver(headerName);
        }

        throw new InvalidOperationException($"Unknown key resolver spec '{spec}'.");
    }
}
