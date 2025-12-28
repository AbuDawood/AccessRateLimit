using System.Linq;
using Microsoft.AspNetCore.Http;

namespace Elf.Core.AccessRateLimit;

/// <summary>
/// Combines multiple resolvers into a single composite key.
/// </summary>
public sealed class CompositeRateLimitKeyResolver : IRateLimitKeyResolver
{
    private readonly IReadOnlyList<IRateLimitKeyResolver> _resolvers;

    /// <summary>
    /// Creates a composite resolver from the provided resolvers.
    /// </summary>
    public CompositeRateLimitKeyResolver(IEnumerable<IRateLimitKeyResolver> resolvers)
    {
        if (resolvers is null)
        {
            throw new ArgumentNullException(nameof(resolvers));
        }

        _resolvers = resolvers.ToArray();
        if (_resolvers.Count == 0)
        {
            throw new ArgumentException("At least one resolver is required.", nameof(resolvers));
        }
    }

    /// <summary>
    /// Resolves and joins all non-empty keys with a pipe separator.
    /// </summary>
    public async ValueTask<string?> ResolveAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        var parts = new List<string>(_resolvers.Count);
        foreach (var resolver in _resolvers)
        {
            var value = await resolver.ResolveAsync(context, cancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(value))
            {
                parts.Add(value);
            }
        }

        if (parts.Count == 0)
        {
            return null;
        }

        return string.Join("|", parts);
    }
}
