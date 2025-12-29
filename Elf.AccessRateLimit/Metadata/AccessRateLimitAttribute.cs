namespace Elf.AccessRateLimit;

/// <summary>
/// Applies an access rate limit policy to an MVC action or controller.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
public sealed class AccessRateLimitAttribute : Attribute
{
    /// <summary>
    /// Creates an attribute for the specified policy name.
    /// </summary>
    public AccessRateLimitAttribute(string policyName)
    {
        if (string.IsNullOrWhiteSpace(policyName))
        {
            throw new ArgumentException("Policy name is required.", nameof(policyName));
        }

        PolicyName = policyName;
    }

    /// <summary>
    /// Policy name to apply.
    /// </summary>
    public string PolicyName { get; }

    /// <summary>
    /// Optional scope override for bucket selection.
    /// </summary>
    public string? Scope { get; set; }

    /// <summary>
    /// Optional per-request cost override (set to a positive value to apply).
    /// </summary>
    public int Cost { get; set; } = -1;
}
