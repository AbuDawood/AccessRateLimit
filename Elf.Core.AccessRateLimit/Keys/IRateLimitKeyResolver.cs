using Microsoft.AspNetCore.Http;

namespace Elf.Core.AccessRateLimit;

/// <summary>
/// Resolves a stable key used to identify the caller.
/// </summary>
public interface IRateLimitKeyResolver
{
    /// <summary>
    /// Resolves a key for the current request, or null to skip limiting.
    /// </summary>
    ValueTask<string?> ResolveAsync(HttpContext context, CancellationToken cancellationToken = default);
}
