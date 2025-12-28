using Microsoft.AspNetCore.Builder;

namespace Elf.Core.AccessRateLimit;

/// <summary>
/// Endpoint convention extensions for access rate limiting.
/// </summary>
public static class AccessRateLimitEndpointConventionBuilderExtensions
{
    /// <summary>
    /// Adds access rate limit metadata to the endpoint.
    /// </summary>
    public static TBuilder RequireAccessRateLimit<TBuilder>(
        this TBuilder builder,
        string policyName,
        string? scope = null,
        int? cost = null)
        where TBuilder : IEndpointConventionBuilder
    {
        if (builder == null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        builder.Add(endpointBuilder =>
        {
            endpointBuilder.Metadata.Add(new AccessRateLimitMetadata(policyName, scope, cost));
        });

        return builder;
    }
}
