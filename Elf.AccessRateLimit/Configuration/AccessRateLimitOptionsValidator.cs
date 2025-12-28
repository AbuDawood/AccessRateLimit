using Microsoft.Extensions.Options;

namespace Elf.AccessRateLimit;

internal sealed class AccessRateLimitOptionsValidator : IValidateOptions<AccessRateLimitOptions>
{
    public ValidateOptionsResult Validate(string? name, AccessRateLimitOptions options)
    {
        if (options == null)
        {
            return ValidateOptionsResult.Fail("Access rate limit options are required.");
        }

        var errors = new List<string>();
        foreach (var entry in options.Policies ?? new Dictionary<string, AccessRateLimitPolicy>())
        {
            try
            {
                AccessRateLimitPolicyNormalizer.Validate(entry.Key, entry.Value);
            }
            catch (Exception ex)
            {
                errors.Add(ex.Message);
            }
        }

        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }
}
