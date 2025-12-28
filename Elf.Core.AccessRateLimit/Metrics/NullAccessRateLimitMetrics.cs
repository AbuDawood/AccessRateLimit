namespace Elf.Core.AccessRateLimit;

internal sealed class NullAccessRateLimitMetrics : IAccessRateLimitMetrics
{
    public void OnAllowed(AccessRateLimitDecision decision)
    {
    }

    public void OnLimited(AccessRateLimitDecision decision)
    {
    }

    public void OnBlocked(AccessRateLimitDecision decision)
    {
    }
}
