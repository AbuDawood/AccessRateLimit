namespace Elf.AccessRateLimit;

internal static class AccessRateLimitPolicyNormalizer
{
    public static AccessRateLimitPolicy Normalize(string name, AccessRateLimitPolicy policy, IRateLimitKeyResolver fallbackResolver)
    {
        var normalized = policy.Clone();
        normalized.Name = name;
        ApplyDefaultsAndValidate(normalized);
        normalized.KeyResolver ??= RateLimitKeyResolverFactory.Create(normalized, fallbackResolver);
        return normalized;
    }

    public static void Validate(string name, AccessRateLimitPolicy policy)
    {
        var normalized = policy.Clone();
        normalized.Name = name;
        ApplyDefaultsAndValidate(normalized);
    }

    private static void ApplyDefaultsAndValidate(AccessRateLimitPolicy policy)
    {
        if (policy.Limit <= 0)
        {
            if (policy.LimitPerSecond.HasValue)
            {
                policy.Limit = policy.LimitPerSecond.Value;
                policy.Window = TimeSpan.FromSeconds(1);
            }
            else if (policy.LimitPerMinute.HasValue)
            {
                policy.Limit = policy.LimitPerMinute.Value;
                policy.Window = TimeSpan.FromMinutes(1);
            }
            else if (policy.LimitPerHour.HasValue)
            {
                policy.Limit = policy.LimitPerHour.Value;
                policy.Window = TimeSpan.FromHours(1);
            }
        }

        if (policy.Limit <= 0)
        {
            throw new InvalidOperationException($"Policy '{policy.Name}' must define a positive limit.");
        }

        if (policy.Window <= TimeSpan.Zero)
        {
            throw new InvalidOperationException($"Policy '{policy.Name}' must define a positive window.");
        }

        if (policy.Cost <= 0)
        {
            policy.Cost = 1;
        }

        if (policy.Cost > policy.Limit)
        {
            throw new InvalidOperationException($"Policy '{policy.Name}' cost must be less than or equal to limit.");
        }

        if (policy.AuthenticatedLimit.HasValue && policy.AuthenticatedLimit.Value <= 0)
        {
            throw new InvalidOperationException($"Policy '{policy.Name}' authenticated limit must be positive.");
        }

        if (policy.AnonymousLimit.HasValue && policy.AnonymousLimit.Value <= 0)
        {
            throw new InvalidOperationException($"Policy '{policy.Name}' anonymous limit must be positive.");
        }

        if (policy.AuthenticatedHeaders != null)
        {
            for (var i = 0; i < policy.AuthenticatedHeaders.Count; i++)
            {
                var header = policy.AuthenticatedHeaders[i];
                if (string.IsNullOrWhiteSpace(header))
                {
                    throw new InvalidOperationException($"Policy '{policy.Name}' authenticated headers must be non-empty.");
                }

                policy.AuthenticatedHeaders[i] = header.Trim();
            }
        }

        if (policy.Penalty == null)
        {
            policy.Penalty = new AccessRateLimitPenaltyOptions();
        }

        if (policy.Penalty.Penalties == null)
        {
            policy.Penalty.Penalties = new List<TimeSpan>();
        }

        if (policy.Penalty.ViolationWindow < TimeSpan.Zero)
        {
            throw new InvalidOperationException($"Policy '{policy.Name}' violation window cannot be negative.");
        }

        if (policy.Penalty.Penalties.Any(p => p <= TimeSpan.Zero))
        {
            throw new InvalidOperationException($"Policy '{policy.Name}' penalties must be positive durations.");
        }

        if (policy.KeyResolver == null &&
            (policy.KeyResolvers == null || policy.KeyResolvers.Count == 0) &&
            string.IsNullOrWhiteSpace(policy.KeyStrategy))
        {
            policy.KeyResolvers = new List<string> { "ip" };
        }
    }
}
