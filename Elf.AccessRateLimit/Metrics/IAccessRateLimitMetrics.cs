namespace Elf.AccessRateLimit;

/// <summary>
/// Metrics hooks for access rate limiting decisions.
/// </summary>
public interface IAccessRateLimitMetrics
{
    /// <summary>
    /// Called when a request is allowed.
    /// </summary>
    void OnAllowed(AccessRateLimitDecision decision);

    /// <summary>
    /// Called when a request is limited but not blocked.
    /// </summary>
    void OnLimited(AccessRateLimitDecision decision);

    /// <summary>
    /// Called when a request is blocked by a penalty.
    /// </summary>
    void OnBlocked(AccessRateLimitDecision decision);
}
