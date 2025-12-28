namespace Elf.AccessRateLimit;

public sealed record AccessRateLimitStoreRequest(
    string BucketKey,
    string BlockKey,
    string ViolationKey,
    int Capacity,
    TimeSpan Window,
    int Cost,
    AccessRateLimitPenaltyOptions Penalty);

public readonly struct AccessRateLimitStoreResult
{
    public AccessRateLimitStoreResult(
        bool allowed,
        bool blocked,
        double remainingTokens,
        int retryAfterSeconds,
        int resetAfterSeconds,
        long violations)
    {
        Allowed = allowed;
        Blocked = blocked;
        RemainingTokens = remainingTokens;
        RetryAfterSeconds = retryAfterSeconds;
        ResetAfterSeconds = resetAfterSeconds;
        Violations = violations;
    }

    public bool Allowed { get; }

    public bool Blocked { get; }

    public double RemainingTokens { get; }

    public int RetryAfterSeconds { get; }

    public int ResetAfterSeconds { get; }

    public long Violations { get; }
}

public interface IAccessRateLimitStore
{
    Task<AccessRateLimitStoreResult> EvaluateAsync(AccessRateLimitStoreRequest request, CancellationToken cancellationToken);
}
