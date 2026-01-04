using Microsoft.AspNetCore.Http;

namespace Elf.AccessRateLimit;

/// <summary>
/// Defines rate limit rules for a named policy.
/// </summary>
public sealed class AccessRateLimitPolicy
{
    /// <summary>
    /// Policy name assigned during registration.
    /// </summary>
    public string Name { get; internal set; } = string.Empty;

    /// <summary>
    /// Max requests per window when no per-period limit is specified.
    /// </summary>
    public int Limit { get; set; }

    /// <summary>
    /// Window size for the limit.
    /// </summary>
    public TimeSpan Window { get; set; }

    /// <summary>
    /// Convenience limit per second (sets Limit and Window).
    /// </summary>
    public int? LimitPerSecond { get; set; }

    /// <summary>
    /// Convenience limit per minute (sets Limit and Window).
    /// </summary>
    public int? LimitPerMinute { get; set; }

    /// <summary>
    /// Convenience limit per hour (sets Limit and Window).
    /// </summary>
    public int? LimitPerHour { get; set; }

    /// <summary>
    /// Token cost per request.
    /// </summary>
    public int Cost { get; set; } = 1;

    /// <summary>
    /// Override limit for authenticated callers.
    /// </summary>
    public int? AuthenticatedLimit { get; set; }

    /// <summary>
    /// Override limit for anonymous callers.
    /// </summary>
    public int? AnonymousLimit { get; set; }

    /// <summary>
    /// Predicate that determines whether a request is authenticated.
    /// </summary>
    public Func<HttpContext, bool>? AuthenticatedWhen { get; set; }

    /// <summary>
    /// Header names that indicate an authenticated request when present.
    /// </summary>
    public List<string>? AuthenticatedHeaders { get; set; }

    /// <summary>
    /// Bucket name to share limits across endpoints.
    /// </summary>
    public string? SharedBucket { get; set; }

    /// <summary>
    /// String-based key resolver specs (ip, header, claim, etc.).
    /// </summary>
    public List<string> KeyResolvers { get; set; } = new();

    /// <summary>
    /// Comma-delimited key resolver specs (alternative to KeyResolvers).
    /// </summary>
    public string? KeyStrategy { get; set; }

    /// <summary>
    /// Explicit key resolver instance for the policy.
    /// </summary>
    public IRateLimitKeyResolver? KeyResolver { get; set; }

    /// <summary>
    /// Penalty escalation options for repeated violations.
    /// </summary>
    public AccessRateLimitPenaltyOptions Penalty { get; set; } = new();

    /// <summary>
    /// Enables or disables the policy.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Predicate that bypasses this policy when it returns true.
    /// </summary>
    public Func<HttpContext, bool>? ExemptWhen { get; set; }

    /// <summary>
    /// Delegate to calculate request cost dynamically.
    /// </summary>
    public Func<HttpContext, int>? CostResolver { get; set; }

    internal AccessRateLimitPolicy Clone()
    {
        return new AccessRateLimitPolicy
        {
            Name = Name,
            Limit = Limit,
            Window = Window,
            LimitPerSecond = LimitPerSecond,
            LimitPerMinute = LimitPerMinute,
            LimitPerHour = LimitPerHour,
            Cost = Cost,
            AuthenticatedLimit = AuthenticatedLimit,
            AnonymousLimit = AnonymousLimit,
            AuthenticatedWhen = AuthenticatedWhen,
            AuthenticatedHeaders = AuthenticatedHeaders == null ? null : new List<string>(AuthenticatedHeaders),
            SharedBucket = SharedBucket,
            KeyResolvers = new List<string>(KeyResolvers ?? new List<string>()),
            KeyStrategy = KeyStrategy,
            KeyResolver = KeyResolver,
            Penalty = (Penalty ?? new AccessRateLimitPenaltyOptions()).Clone(),
            Enabled = Enabled,
            ExemptWhen = ExemptWhen,
            CostResolver = CostResolver
        };
    }

    internal int ResolveLimit(HttpContext context)
    {
        return ResolveLimit(context, options: null);
    }

    internal int ResolveLimit(HttpContext context, AccessRateLimitOptions? options)
    {
        var isAuthenticated = ResolveIsAuthenticated(context, options);
        if (isAuthenticated && AuthenticatedLimit.HasValue)
        {
            return AuthenticatedLimit.Value;
        }

        if (!isAuthenticated && AnonymousLimit.HasValue)
        {
            return AnonymousLimit.Value;
        }

        return Limit;
    }

    private bool ResolveIsAuthenticated(HttpContext context, AccessRateLimitOptions? options)
    {
        if (AuthenticatedWhen != null)
        {
            return AuthenticatedWhen(context);
        }

        if (options?.AuthenticatedWhen != null)
        {
            return options.AuthenticatedWhen(context);
        }

        if (context.User?.Identity?.IsAuthenticated == true)
        {
            return true;
        }

        var headerNames = AuthenticatedHeaders ?? options?.AuthenticatedHeaders;
        return HasAuthenticatedHeader(context, headerNames);
    }

    private static bool HasAuthenticatedHeader(HttpContext context, IReadOnlyList<string>? headerNames)
    {
        if (headerNames == null || headerNames.Count == 0)
        {
            return false;
        }

        foreach (var headerName in headerNames)
        {
            if (string.IsNullOrWhiteSpace(headerName))
            {
                continue;
            }

            var trimmed = headerName.Trim();
            if (!context.Request.Headers.TryGetValue(trimmed, out var values))
            {
                continue;
            }

            foreach (var value in values)
            {
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return true;
                }
            }
        }

        return false;
    }

    internal int ResolveCost(HttpContext context, int? overrideCost)
    {
        if (overrideCost.HasValue)
        {
            return overrideCost.Value;
        }

        if (CostResolver != null)
        {
            return CostResolver(context);
        }

        return Cost;
    }
}
