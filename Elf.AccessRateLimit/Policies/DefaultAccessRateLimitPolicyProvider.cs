using Microsoft.Extensions.Options;

namespace Elf.AccessRateLimit;

internal sealed class DefaultAccessRateLimitPolicyProvider : IAccessRateLimitPolicyProvider
{
    private readonly IOptionsMonitor<AccessRateLimitOptions> _optionsMonitor;
    private volatile PolicyCache _cache;

    public DefaultAccessRateLimitPolicyProvider(IOptionsMonitor<AccessRateLimitOptions> optionsMonitor)
    {
        _optionsMonitor = optionsMonitor;
        _cache = BuildCache(optionsMonitor.CurrentValue);
        _optionsMonitor.OnChange(options => _cache = BuildCache(options));
    }

    public AccessRateLimitPolicy? GetPolicy(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return null;
        }

        return _cache.Policies.TryGetValue(name, out var policy) ? policy : null;
    }

    public AccessRateLimitPolicy? GetDefaultPolicy()
    {
        if (string.IsNullOrWhiteSpace(_cache.DefaultPolicyName))
        {
            return null;
        }

        return GetPolicy(_cache.DefaultPolicyName);
    }

    private static PolicyCache BuildCache(AccessRateLimitOptions options)
    {
        var policies = new Dictionary<string, AccessRateLimitPolicy>(StringComparer.OrdinalIgnoreCase);
        var fallbackResolver = options.FallbackKeyResolver ?? new IpRateLimitKeyResolver();

        foreach (var entry in options.Policies ?? new Dictionary<string, AccessRateLimitPolicy>())
        {
            var normalized = AccessRateLimitPolicyNormalizer.Normalize(entry.Key, entry.Value, fallbackResolver);
            policies[entry.Key] = normalized;
        }

        return new PolicyCache(policies, options.DefaultPolicyName);
    }

    private sealed class PolicyCache
    {
        public PolicyCache(Dictionary<string, AccessRateLimitPolicy> policies, string? defaultPolicyName)
        {
            Policies = policies;
            DefaultPolicyName = defaultPolicyName;
        }

        public Dictionary<string, AccessRateLimitPolicy> Policies { get; }

        public string? DefaultPolicyName { get; }
    }
}
