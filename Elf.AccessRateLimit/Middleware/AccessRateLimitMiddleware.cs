using System.Globalization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Elf.AccessRateLimit;

/// <summary>
/// ASP.NET Core middleware that enforces access rate limits.
/// </summary>
public sealed class AccessRateLimitMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IAccessRateLimitPolicyProvider _policyProvider;
    private readonly IAccessRateLimitStore _store;
    private readonly IOptionsMonitor<AccessRateLimitOptions> _options;
    private readonly IAccessRateLimitMetrics _metrics;
    private readonly ILogger<AccessRateLimitMiddleware> _logger;

    public AccessRateLimitMiddleware(
        RequestDelegate next,
        IAccessRateLimitPolicyProvider policyProvider,
        IAccessRateLimitStore store,
        IOptionsMonitor<AccessRateLimitOptions> options,
        IAccessRateLimitMetrics metrics,
        ILogger<AccessRateLimitMiddleware> logger)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _policyProvider = policyProvider ?? throw new ArgumentNullException(nameof(policyProvider));
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _metrics = metrics ?? throw new ArgumentNullException(nameof(metrics));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Evaluates the request against the configured rate limit policy.
    /// </summary>
    public async Task InvokeAsync(HttpContext context)
    {
        var endpoint = context.GetEndpoint();
        var options = _options.CurrentValue;
        var logDetail = options.Logging.Detail;
        var metadata = ResolveMetadata(endpoint);

        // Resolve policy name from endpoint metadata or defaults.
        var policyName = metadata?.PolicyName ?? options.DefaultPolicyName;
        if (string.IsNullOrWhiteSpace(policyName))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        var policy = _policyProvider.GetPolicy(policyName);
        if (policy == null)
        {
            _logger.LogWarning("Access rate limit policy {Policy} was not found.", policyName);
            await _next(context).ConfigureAwait(false);
            return;
        }

        // Skip evaluation for disabled or exempt requests.
        if (!policy.Enabled)
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        if (options.ExemptWhen?.Invoke(context) == true || policy.ExemptWhen?.Invoke(context) == true)
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        // Resolve the bucket scope and caller key.
        var scope = ResolveScope(endpoint, policy, metadata);
        var key = await ResolveKeyAsync(context, policy, options).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(key))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        var cost = policy.ResolveCost(context, metadata?.Cost);
        if (cost <= 0)
        {
            cost = 1;
        }

        var limit = policy.ResolveLimit(context);
        if (cost > limit)
        {
            cost = limit;
        }
        // Hash the key before writing to Redis.
        var keyHash = AccessRateLimitKeyUtilities.Hash(key);
        var scopeKey = AccessRateLimitKeyUtilities.NormalizeSegment(scope);
        var bucketKey = $"{options.RedisKeyPrefix}:bucket:{policy.Name}:{scopeKey}:{keyHash}";
        var blockKey = $"{options.RedisKeyPrefix}:block:{policy.Name}:{scopeKey}:{keyHash}";
        var violationKey = $"{options.RedisKeyPrefix}:viol:{policy.Name}:{scopeKey}:{keyHash}";

        AccessRateLimitStoreResult storeResult;
        try
        {
            // Perform the atomic evaluation in Redis.
            storeResult = await _store.EvaluateAsync(
                new AccessRateLimitStoreRequest(bucketKey, blockKey, violationKey, limit, policy.Window, cost, policy.Penalty),
                context.RequestAborted).ConfigureAwait(false);
        }
        catch (Exception ex) when (options.FailOpen)
        {
            _logger.LogError(ex, "Access rate limit failed open for policy {Policy}.", policy.Name);
            await _next(context).ConfigureAwait(false);
            return;
        }

        var remaining = (int)Math.Floor(Math.Max(0, storeResult.RemainingTokens));
        var retryAfter = TimeSpan.FromSeconds(storeResult.RetryAfterSeconds);
        var resetAfterSeconds = storeResult.ResetAfterSeconds > 0
            ? storeResult.ResetAfterSeconds
            : storeResult.RetryAfterSeconds;
        var resetAt = DateTimeOffset.UtcNow.AddSeconds(resetAfterSeconds);
        var decision = new AccessRateLimitDecision(
            policy.Name,
            scope,
            keyHash,
            limit,
            remaining,
            cost,
            retryAfter,
            resetAt,
            storeResult.Allowed,
            storeResult.Blocked,
            storeResult.Violations);

        if (storeResult.Allowed)
        {
            if (options.AddRateLimitHeaders)
            {
                SetRateLimitHeaders(context, decision);
            }

            _metrics.OnAllowed(decision);
            if (logDetail == AccessRateLimitLogDetail.Detailed)
            {
                _logger.LogInformation(
                    "Access rate limit allowed policy={Policy} scope={Scope} key={KeyHash} limit={Limit} remaining={Remaining} cost={Cost} resetAt={ResetAt}",
                    decision.PolicyName,
                    decision.Scope,
                    AccessRateLimitKeyUtilities.Fingerprint(decision.KeyHash),
                    decision.Limit,
                    decision.Remaining,
                    decision.Cost,
                    decision.Reset);
            }

            await _next(context).ConfigureAwait(false);
            return;
        }

        context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        if (options.AddRateLimitHeaders)
        {
            SetRateLimitHeaders(context, decision);
        }
        SetRetryAfterHeader(context, decision);

        // Emit logs/metrics before writing the response body.
        if (storeResult.Blocked)
        {
            _metrics.OnBlocked(decision);
            if (logDetail == AccessRateLimitLogDetail.Detailed)
            {
                _logger.LogWarning(
                    "Access rate limit blocked policy={Policy} scope={Scope} key={KeyHash} limit={Limit} remaining={Remaining} cost={Cost} retryAfter={RetryAfterSeconds} violations={Violations} resetAt={ResetAt}",
                    decision.PolicyName,
                    decision.Scope,
                    AccessRateLimitKeyUtilities.Fingerprint(decision.KeyHash),
                    decision.Limit,
                    decision.Remaining,
                    decision.Cost,
                    (int)Math.Ceiling(decision.RetryAfter.TotalSeconds),
                    decision.Violations,
                    decision.Reset);
            }
            else
            {
                _logger.LogWarning(
                    "Access rate limit blocked policy={Policy} scope={Scope} key={KeyHash} retryAfter={RetryAfterSeconds} violations={Violations}",
                    decision.PolicyName,
                    decision.Scope,
                    AccessRateLimitKeyUtilities.Fingerprint(decision.KeyHash),
                    (int)Math.Ceiling(decision.RetryAfter.TotalSeconds),
                    decision.Violations);
            }
        }
        else
        {
            _metrics.OnLimited(decision);
            if (logDetail == AccessRateLimitLogDetail.Detailed)
            {
                _logger.LogInformation(
                    "Access rate limit limited policy={Policy} scope={Scope} key={KeyHash} limit={Limit} remaining={Remaining} cost={Cost} retryAfter={RetryAfterSeconds} violations={Violations} resetAt={ResetAt}",
                    decision.PolicyName,
                    decision.Scope,
                    AccessRateLimitKeyUtilities.Fingerprint(decision.KeyHash),
                    decision.Limit,
                    decision.Remaining,
                    decision.Cost,
                    (int)Math.Ceiling(decision.RetryAfter.TotalSeconds),
                    decision.Violations,
                    decision.Reset);
            }
            else
            {
                _logger.LogInformation(
                    "Access rate limit limited policy={Policy} scope={Scope} key={KeyHash} retryAfter={RetryAfterSeconds}",
                    decision.PolicyName,
                    decision.Scope,
                    AccessRateLimitKeyUtilities.Fingerprint(decision.KeyHash),
                    (int)Math.Ceiling(decision.RetryAfter.TotalSeconds));
            }
        }

        if (options.Response.OnRejected != null)
        {
            await options.Response.OnRejected(context, decision).ConfigureAwait(false);
        }
        else if (!string.IsNullOrWhiteSpace(options.Response.Body))
        {
            if (!string.IsNullOrWhiteSpace(options.Response.ContentType))
            {
                context.Response.ContentType = options.Response.ContentType;
            }

            await context.Response.WriteAsync(options.Response.Body, context.RequestAborted).ConfigureAwait(false);
        }
    }

    private static AccessRateLimitMetadata? ResolveMetadata(Endpoint? endpoint)
    {
        if (endpoint == null)
        {
            return null;
        }

        var metadata = endpoint.Metadata.GetOrderedMetadata<AccessRateLimitMetadata>();
        if (metadata.Count > 0)
        {
            return metadata[^1];
        }

        var attributes = endpoint.Metadata.GetOrderedMetadata<AccessRateLimitAttribute>();
        if (attributes.Count > 0)
        {
            var attribute = attributes[^1];
            var cost = attribute.Cost > 0 ? attribute.Cost : (int?)null;
            return new AccessRateLimitMetadata(attribute.PolicyName, attribute.Scope, cost);
        }

        return null;
    }

    private static string ResolveScope(Endpoint? endpoint, AccessRateLimitPolicy policy, AccessRateLimitMetadata? metadata)
    {
        if (!string.IsNullOrWhiteSpace(metadata?.Scope))
        {
            return metadata.Scope!;
        }

        if (!string.IsNullOrWhiteSpace(policy.SharedBucket))
        {
            return policy.SharedBucket!;
        }

        if (endpoint is RouteEndpoint routeEndpoint)
        {
            return routeEndpoint.RoutePattern.RawText
                ?? routeEndpoint.RoutePattern.ToString()
                ?? "unknown";
        }

        return endpoint?.DisplayName ?? "unknown";
    }

    private static async Task<string?> ResolveKeyAsync(
        HttpContext context,
        AccessRateLimitPolicy policy,
        AccessRateLimitOptions options)
    {
        var keyResolver = policy.KeyResolver ?? options.FallbackKeyResolver;
        if (keyResolver == null)
        {
            return null;
        }

        var key = await keyResolver.ResolveAsync(context, context.RequestAborted).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(key))
        {
            return key;
        }

        if (options.FallbackKeyResolver != null && !ReferenceEquals(keyResolver, options.FallbackKeyResolver))
        {
            return await options.FallbackKeyResolver.ResolveAsync(context, context.RequestAborted).ConfigureAwait(false);
        }

        return null;
    }

    private static void SetRateLimitHeaders(HttpContext context, AccessRateLimitDecision decision)
    {
        context.Response.Headers["X-RateLimit-Limit"] = decision.Limit.ToString(CultureInfo.InvariantCulture);
        context.Response.Headers["X-RateLimit-Remaining"] = decision.Remaining.ToString(CultureInfo.InvariantCulture);
        context.Response.Headers["X-RateLimit-Reset"] = decision.Reset.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
    }

    private static void SetRetryAfterHeader(HttpContext context, AccessRateLimitDecision decision)
    {
        context.Response.Headers["Retry-After"] =
            ((int)Math.Ceiling(decision.RetryAfter.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
    }
}
