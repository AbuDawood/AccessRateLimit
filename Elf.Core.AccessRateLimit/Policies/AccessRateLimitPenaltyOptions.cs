namespace Elf.Core.AccessRateLimit;

/// <summary>
/// Escalating penalty configuration for repeated violations.
/// </summary>
public sealed class AccessRateLimitPenaltyOptions
{
    /// <summary>
    /// Enables penalty escalation when limits are exceeded.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Window that counts violations for escalation.
    /// </summary>
    public TimeSpan ViolationWindow { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Ordered block durations applied per violation (capped at last entry).
    /// </summary>
    public List<TimeSpan> Penalties { get; set; } = new()
    {
        TimeSpan.FromSeconds(10),
        TimeSpan.FromMinutes(1),
        TimeSpan.FromMinutes(5),
        TimeSpan.FromMinutes(30)
    };

    internal AccessRateLimitPenaltyOptions Clone()
    {
        return new AccessRateLimitPenaltyOptions
        {
            Enabled = Enabled,
            ViolationWindow = ViolationWindow,
            Penalties = new List<TimeSpan>(Penalties ?? new List<TimeSpan>())
        };
    }
}
