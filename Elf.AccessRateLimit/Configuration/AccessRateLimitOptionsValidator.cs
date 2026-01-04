using System.Linq;
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

        if (options.AuthenticatedHeaders != null)
        {
            if (options.AuthenticatedHeaders.Any(string.IsNullOrWhiteSpace))
            {
                errors.Add("Authenticated headers must be non-empty.");
            }
        }

        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }
}
