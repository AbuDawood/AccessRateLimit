namespace Elf.AccessRateLimit;

/// <summary>
/// Represents the outcome of a rate limit evaluation.
/// </summary>
public sealed class AccessRateLimitDecision
{
    /// <summary>
    /// Creates a new decision instance.
    /// </summary>
    public AccessRateLimitDecision(
        string policyName,
        string scope,
        string keyHash,
        int limit,
        int remaining,
        int cost,
        TimeSpan retryAfter,
        DateTimeOffset reset,
        bool allowed,
        bool blocked,
        long violations)
    {
        PolicyName = policyName;
        Scope = scope;
        KeyHash = keyHash;
        Limit = limit;
        Remaining = remaining;
        Cost = cost;
        RetryAfter = retryAfter;
        Reset = reset;
        Allowed = allowed;
        Blocked = blocked;
        Violations = violations;
    }

    /// <summary>
    /// Policy name used for evaluation.
    /// </summary>
    public string PolicyName { get; }

    /// <summary>
    /// Scope or bucket used for the decision.
    /// </summary>
    public string Scope { get; }

    /// <summary>
    /// Hash of the resolved caller key.
    /// </summary>
    public string KeyHash { get; }

    /// <summary>
    /// Maximum allowed tokens in the window.
    /// </summary>
    public int Limit { get; }

    /// <summary>
    /// Remaining tokens after evaluation.
    /// </summary>
    public int Remaining { get; }

    /// <summary>
    /// Token cost applied to the request.
    /// </summary>
    public int Cost { get; }

    /// <summary>
    /// Duration before another request is allowed.
    /// </summary>
    public TimeSpan RetryAfter { get; }

    /// <summary>
    /// Timestamp when the window resets.
    /// </summary>
    public DateTimeOffset Reset { get; }

    /// <summary>
    /// Indicates whether the request is allowed.
    /// </summary>
    public bool Allowed { get; }

    /// <summary>
    /// Indicates whether the request is blocked by a penalty.
    /// </summary>
    public bool Blocked { get; }

    /// <summary>
    /// Number of violations within the penalty window.
    /// </summary>
    public long Violations { get; }
}
