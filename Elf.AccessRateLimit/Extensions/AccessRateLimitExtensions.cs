using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Elf.AccessRateLimit;

/// <summary>
/// Service registration and middleware extensions.
/// </summary>
public static class AccessRateLimitExtensions
{
    /// <summary>
    /// Registers access rate limiting with a code-based configuration.
    /// </summary>
    public static IServiceCollection AddElfAccessRateLimit(
        this IServiceCollection services,
        Action<AccessRateLimitOptions> configure)
    {
        if (services == null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        if (configure == null)
        {
            throw new ArgumentNullException(nameof(configure));
        }

        services.AddOptions<AccessRateLimitOptions>().Configure(configure);
        RegisterServices(services);
        return services;
    }

    /// <summary>
    /// Registers access rate limiting using the default configuration section.
    /// </summary>
    public static IServiceCollection AddElfAccessRateLimit(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        if (services == null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        if (configuration == null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        return services.AddElfAccessRateLimit(configuration.GetSection("Elf:AccessRateLimit"));
    }

    /// <summary>
    /// Registers access rate limiting using a specific configuration section.
    /// </summary>
    public static IServiceCollection AddElfAccessRateLimit(
        this IServiceCollection services,
        IConfigurationSection section)
    {
        if (services == null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        if (section == null)
        {
            throw new ArgumentNullException(nameof(section));
        }

        services.AddOptions<AccessRateLimitOptions>().Bind(section);
        RegisterServices(services);
        return services;
    }

    /// <summary>
    /// Adds the access rate limiting middleware to the pipeline.
    /// </summary>
    public static IApplicationBuilder UseElfAccessRateLimit(this IApplicationBuilder app)
    {
        if (app == null)
        {
            throw new ArgumentNullException(nameof(app));
        }

        return app.UseMiddleware<AccessRateLimitMiddleware>();
    }

    private static void RegisterServices(IServiceCollection services)
    {
        services.TryAddSingleton<IAccessRateLimitPolicyProvider, DefaultAccessRateLimitPolicyProvider>();
        services.TryAddSingleton<IAccessRateLimitStore, RedisRateLimitStore>();
        services.TryAddSingleton<IAccessRateLimitMetrics, NullAccessRateLimitMetrics>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<AccessRateLimitOptions>, AccessRateLimitOptionsValidator>());
    }
}
