namespace Elf.AccessRateLimit;

/// <summary>
/// Endpoint metadata for access rate limiting.
/// </summary>
public sealed class AccessRateLimitMetadata
{
    /// <summary>
    /// Creates metadata for the specified policy and optional scope/cost.
    /// </summary>
    public AccessRateLimitMetadata(string policyName, string? scope = null, int? cost = null)
    {
        if (string.IsNullOrWhiteSpace(policyName))
        {
            throw new ArgumentException("Policy name is required.", nameof(policyName));
        }

        PolicyName = policyName;
        Scope = scope;
        Cost = cost;
    }

    /// <summary>
    /// Policy name to apply.
    /// </summary>
    public string PolicyName { get; }

    /// <summary>
    /// Optional scope override for bucket selection.
    /// </summary>
    public string? Scope { get; }

    /// <summary>
    /// Optional per-request cost override.
    /// </summary>
    public int? Cost { get; }
}
