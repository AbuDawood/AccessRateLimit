using Microsoft.AspNetCore.Http;

namespace Elf.Core.AccessRateLimit;

/// <summary>
/// Global configuration for access rate limiting.
/// </summary>
public sealed class AccessRateLimitOptions
{
    /// <summary>
    /// Named policy definitions keyed by policy name.
    /// </summary>
    public IDictionary<string, AccessRateLimitPolicy> Policies { get; set; } =
        new Dictionary<string, AccessRateLimitPolicy>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Default policy name when an endpoint does not specify one.
    /// </summary>
    public string? DefaultPolicyName { get; set; }

    /// <summary>
    /// Prefix for all Redis keys created by the limiter.
    /// </summary>
    public string RedisKeyPrefix { get; set; } = "elf:accessrl";

    /// <summary>
    /// Adds X-RateLimit headers to responses when enabled.
    /// </summary>
    public bool AddRateLimitHeaders { get; set; } = true;

    /// <summary>
    /// Allows requests if Redis is unavailable when set to true.
    /// </summary>
    public bool FailOpen { get; set; } = true;

    /// <summary>
    /// Key resolver used when a policy does not provide a resolver or resolves no key.
    /// </summary>
    public IRateLimitKeyResolver? FallbackKeyResolver { get; set; } = new IpRateLimitKeyResolver();

    /// <summary>
    /// Predicate that bypasses all rate limiting when it returns true.
    /// </summary>
    public Func<HttpContext, bool>? ExemptWhen { get; set; }

    /// <summary>
    /// Response customization for rejected requests.
    /// </summary>
    public AccessRateLimitResponseOptions Response { get; set; } = new();

    /// <summary>
    /// Adds or replaces a named policy definition.
    /// </summary>
    public AccessRateLimitOptions AddPolicy(string name, Action<AccessRateLimitPolicyBuilder> configure)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("Policy name is required.", nameof(name));
        }

        if (configure is null)
        {
            throw new ArgumentNullException(nameof(configure));
        }

        var policy = new AccessRateLimitPolicy();
        var builder = new AccessRateLimitPolicyBuilder(policy);
        configure(builder);
        policy.Name = name;
        Policies[name] = policy;
        return this;
    }
}

/// <summary>
/// Response customization for rate-limited requests.
/// </summary>
public sealed class AccessRateLimitResponseOptions
{
    /// <summary>
    /// Content type used when writing a default response body.
    /// </summary>
    public string? ContentType { get; set; } = "text/plain";

    /// <summary>
    /// Body written when a request is rejected and no custom handler is set.
    /// </summary>
    public string? Body { get; set; } = "Too many requests.";

    /// <summary>
    /// Custom response handler for rejected requests.
    /// </summary>
    public Func<HttpContext, AccessRateLimitDecision, Task>? OnRejected { get; set; }
}
