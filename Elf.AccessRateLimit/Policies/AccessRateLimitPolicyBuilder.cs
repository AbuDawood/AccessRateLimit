using Microsoft.AspNetCore.Http;

namespace Elf.AccessRateLimit;

/// <summary>
/// Fluent builder for configuring a rate limit policy.
/// </summary>
public sealed class AccessRateLimitPolicyBuilder
{
    private readonly AccessRateLimitPolicy _policy;

    /// <summary>
    /// Creates a builder for the specified policy instance.
    /// </summary>
    public AccessRateLimitPolicyBuilder(AccessRateLimitPolicy policy)
    {
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
    }

    /// <summary>
    /// Sets the max requests and time window.
    /// </summary>
    public AccessRateLimitPolicyBuilder WithLimit(int limit, TimeSpan window)
    {
        _policy.Limit = limit;
        _policy.Window = window;
        return this;
    }

    /// <summary>
    /// Sets a per-second limit (Window will be 1 second).
    /// </summary>
    public AccessRateLimitPolicyBuilder WithLimitPerSecond(int limit)
    {
        _policy.LimitPerSecond = limit;
        return this;
    }

    /// <summary>
    /// Sets a per-minute limit (Window will be 1 minute).
    /// </summary>
    public AccessRateLimitPolicyBuilder WithLimitPerMinute(int limit)
    {
        _policy.LimitPerMinute = limit;
        return this;
    }

    /// <summary>
    /// Sets a per-hour limit (Window will be 1 hour).
    /// </summary>
    public AccessRateLimitPolicyBuilder WithLimitPerHour(int limit)
    {
        _policy.LimitPerHour = limit;
        return this;
    }

    /// <summary>
    /// Sets a fixed token cost per request.
    /// </summary>
    public AccessRateLimitPolicyBuilder WithCost(int cost)
    {
        _policy.Cost = cost;
        return this;
    }

    /// <summary>
    /// Sets a limit override for authenticated callers.
    /// </summary>
    public AccessRateLimitPolicyBuilder ForAuthenticated(int limit)
    {
        _policy.AuthenticatedLimit = limit;
        return this;
    }

    /// <summary>
    /// Sets a limit override for anonymous callers.
    /// </summary>
    public AccessRateLimitPolicyBuilder ForAnonymous(int limit)
    {
        _policy.AnonymousLimit = limit;
        return this;
    }

    /// <summary>
    /// Sets a predicate to determine whether a request is authenticated.
    /// </summary>
    public AccessRateLimitPolicyBuilder AuthenticatedWhen(Func<HttpContext, bool> predicate)
    {
        if (predicate is null)
        {
            throw new ArgumentNullException(nameof(predicate));
        }

        _policy.AuthenticatedWhen = predicate;
        return this;
    }

    /// <summary>
    /// Sets header names that indicate an authenticated request when present.
    /// </summary>
    public AccessRateLimitPolicyBuilder WithAuthenticatedHeaders(params string[] headers)
    {
        if (headers == null || headers.Length == 0)
        {
            throw new ArgumentException("At least one header name is required.", nameof(headers));
        }

        var normalized = new List<string>(headers.Length);
        foreach (var header in headers)
        {
            if (string.IsNullOrWhiteSpace(header))
            {
                throw new ArgumentException("Header names cannot be empty.", nameof(headers));
            }

            normalized.Add(header.Trim());
        }

        _policy.AuthenticatedHeaders = normalized;
        return this;
    }

    /// <summary>
    /// Uses a shared bucket name across endpoints.
    /// </summary>
    public AccessRateLimitPolicyBuilder WithSharedBucket(string bucket)
    {
        _policy.SharedBucket = bucket;
        return this;
    }

    /// <summary>
    /// Sets a custom key resolver instance.
    /// </summary>
    public AccessRateLimitPolicyBuilder WithKeyResolver(IRateLimitKeyResolver resolver)
    {
        if (resolver == null)
        {
            throw new ArgumentNullException(nameof(resolver));
        }

        _policy.KeyResolver = resolver;
        return this;
    }

    /// <summary>
    /// Combines multiple resolvers into a composite resolver.
    /// </summary>
    public AccessRateLimitPolicyBuilder WithKeyResolvers(params IRateLimitKeyResolver[] resolvers)
    {
        if (resolvers == null || resolvers.Length == 0)
        {
            throw new ArgumentException("At least one resolver is required.", nameof(resolvers));
        }

        _policy.KeyResolver = new CompositeRateLimitKeyResolver(resolvers);
        return this;
    }

    /// <summary>
    /// Sets resolver specs (ip, header, claim, etc.).
    /// </summary>
    public AccessRateLimitPolicyBuilder WithKeyResolverSpecs(params string[] specs)
    {
        if (specs == null || specs.Length == 0)
        {
            throw new ArgumentException("At least one resolver spec is required.", nameof(specs));
        }

        _policy.KeyResolvers = new List<string>(specs);
        return this;
    }

    /// <summary>
    /// Configures escalation penalties for violations.
    /// </summary>
    public AccessRateLimitPolicyBuilder WithPenalty(Action<AccessRateLimitPenaltyOptions> configure)
    {
        if (configure is null)
        {
            throw new ArgumentNullException(nameof(configure));
        }

        configure(_policy.Penalty);
        return this;
    }

    /// <summary>
    /// Adds a predicate that bypasses this policy when true.
    /// </summary>
    public AccessRateLimitPolicyBuilder ExemptWhen(Func<HttpContext, bool> predicate)
    {
        _policy.ExemptWhen = predicate;
        return this;
    }

    /// <summary>
    /// Sets a delegate to compute request cost per call.
    /// </summary>
    public AccessRateLimitPolicyBuilder WithCostResolver(Func<HttpContext, int> resolver)
    {
        _policy.CostResolver = resolver;
        return this;
    }
}
