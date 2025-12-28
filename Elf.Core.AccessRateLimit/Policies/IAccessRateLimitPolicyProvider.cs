namespace Elf.Core.AccessRateLimit;

/// <summary>
/// Provides resolved rate limit policies by name.
/// </summary>
public interface IAccessRateLimitPolicyProvider
{
    /// <summary>
    /// Returns a policy by name, or null when not found.
    /// </summary>
    AccessRateLimitPolicy? GetPolicy(string name);

    /// <summary>
    /// Returns the default policy when configured.
    /// </summary>
    AccessRateLimitPolicy? GetDefaultPolicy();
}
