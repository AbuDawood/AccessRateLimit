using System.Globalization;
using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using StackExchange.Redis;
using Elf.AccessRateLimit;

internal static class Program
{
    private const string DefaultRedis = "localhost:6379";
    private const string DefaultBaseUrl = "http://127.0.0.1:5055";

    private const int DownloadLimit = 3;
    private static readonly TimeSpan DownloadWindow = TimeSpan.FromSeconds(10);

    private const int ExportLimit = 4;
    private static readonly TimeSpan ExportWindow = TimeSpan.FromSeconds(10);

    public static async Task<int> Main(string[] args)
    {
        var options = SampleOptions.Parse(args);
        if (options.ShowHelp)
        {
            SampleOptions.PrintUsage();
            return 0;
        }

        WebApplication app;
        try
        {
            app = BuildHost(options);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Failed to build sample host: {0}", ex.Message);
            return 1;
        }

        try
        {
            await app.StartAsync();
        }
        catch (Exception ex)
        {
            Console.WriteLine("Failed to start sample host: {0}", ex.Message);
            return 1;
        }

        try
        {
            using var client = new HttpClient { BaseAddress = new Uri(options.BaseUrl) };

            var sample = options.Sample.ToLowerInvariant();
            if (sample == "all" || sample == "basic")
            {
                await RunBasicSampleAsync(client);
            }

            if (sample == "all" || sample == "keys")
            {
                await RunKeySampleAsync(client);
            }

            if (sample == "all" || sample == "escalation")
            {
                await RunEscalationSampleAsync(client);
            }
        }
        finally
        {
            await app.StopAsync();
            await app.DisposeAsync();
        }

        return 0;
    }

    private static WebApplication BuildHost(SampleOptions options)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = Array.Empty<string>(),
            ApplicationName = typeof(Program).Assembly.FullName
        });

        builder.WebHost.UseUrls(options.BaseUrl);

        builder.Services.AddSingleton<IConnectionMultiplexer>(
            _ => ConnectionMultiplexer.Connect(options.RedisConnectionString));

        builder.Services.AddElfAccessRateLimit(rateLimitOptions =>
        {
            rateLimitOptions.RedisKeyPrefix = "elf:accessrl:samples";
            rateLimitOptions.DefaultPolicyName = "download";
            rateLimitOptions.AddPolicy("download", policy =>
            {
                policy.WithLimit(DownloadLimit, DownloadWindow);
                policy.WithKeyResolverSpecs("ip");
                policy.WithPenalty(penalty =>
                {
                    penalty.ViolationWindow = TimeSpan.FromSeconds(30);
                    penalty.Penalties = new List<TimeSpan>
                    {
                        TimeSpan.FromSeconds(2),
                        TimeSpan.FromSeconds(5),
                        TimeSpan.FromSeconds(15)
                    };
                });
            });

            rateLimitOptions.AddPolicy("export", policy =>
            {
                policy.WithLimit(ExportLimit, ExportWindow);
                policy.WithKeyResolverSpecs("header:X-Api-Key");
            });
        });

        var app = builder.Build();

        app.UseElfAccessRateLimit();

        app.MapGet("/download/{id}", (string id) => Results.Ok(new { id, ok = true }))
            .RequireAccessRateLimit("download");

        app.MapGet("/export/{id}", (string id) => Results.Ok(new { id, ok = true }))
            .RequireAccessRateLimit("export", cost: 2);

        app.MapGet("/status", () => Results.Ok("ok"));

        return app;
    }

    private static async Task RunBasicSampleAsync(HttpClient client)
    {
        Console.WriteLine("== Basic sample: download limit {0} per {1}s ==", DownloadLimit, DownloadWindow.TotalSeconds);

        for (var i = 0; i < DownloadLimit + 1; i++)
        {
            var snapshot = await CallAsync(client, "/download/1");
            PrintSnapshot("download", snapshot);
            await Task.Delay(150);
        }

        Console.WriteLine();
    }

    private static async Task RunKeySampleAsync(HttpClient client)
    {
        Console.WriteLine("== Key sample: export limit {0} per {1}s, cost=2, key=X-Api-Key ==", ExportLimit, ExportWindow.TotalSeconds);

        var keyA = "alpha";
        var keyB = "bravo";

        for (var i = 0; i < 3; i++)
        {
            var snapshotA = await CallAsync(client, "/export/1", keyA);
            PrintSnapshot($"export:{keyA}", snapshotA);

            var snapshotB = await CallAsync(client, "/export/1", keyB);
            PrintSnapshot($"export:{keyB}", snapshotB);
        }

        Console.WriteLine();
    }

    private static async Task RunEscalationSampleAsync(HttpClient client)
    {
        Console.WriteLine("== Escalation sample: repeated violations increase block duration ==");

        for (var round = 1; round <= 3; round++)
        {
            var retryAfter = await TriggerViolationAsync(client, round);
            if (retryAfter <= 0)
            {
                break;
            }

            await Task.Delay(TimeSpan.FromSeconds(retryAfter + 1));
        }

        Console.WriteLine();
    }

    private static async Task<int> TriggerViolationAsync(HttpClient client, int round)
    {
        Console.WriteLine("Round {0}: sending {1} requests to trigger violation", round, DownloadLimit + 1);
        int retryAfter = 0;

        for (var i = 0; i < DownloadLimit + 1; i++)
        {
            var snapshot = await CallAsync(client, "/download/1");
            PrintSnapshot("download", snapshot);
            retryAfter = snapshot.RetryAfterSeconds ?? retryAfter;
            await Task.Delay(150);
        }

        Console.WriteLine("Waiting {0}s before next round...", retryAfter + 1);
        return retryAfter;
    }

    private static async Task<ResponseSnapshot> CallAsync(HttpClient client, string path, string? apiKey = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        if (!string.IsNullOrWhiteSpace(apiKey))
        {
            request.Headers.Add("X-Api-Key", apiKey);
        }

        using var response = await client.SendAsync(request);
        return ResponseSnapshot.From(response);
    }

    private static void PrintSnapshot(string label, ResponseSnapshot snapshot)
    {
        Console.WriteLine(
            "{0,-14} {1,3} limit={2,-3} remaining={3,-3} retry-after={4}",
            label,
            (int)snapshot.StatusCode,
            snapshot.Limit?.ToString(CultureInfo.InvariantCulture) ?? "-",
            snapshot.Remaining?.ToString(CultureInfo.InvariantCulture) ?? "-",
            snapshot.RetryAfterSeconds?.ToString(CultureInfo.InvariantCulture) ?? "-");
    }

    private sealed record SampleOptions
    {
        public string RedisConnectionString { get; init; } = DefaultRedis;

        public string BaseUrl { get; init; } = DefaultBaseUrl;

        public string Sample { get; init; } = "all";

        public bool ShowHelp { get; init; }

        public static SampleOptions Parse(string[] args)
        {
            var options = new SampleOptions();
            for (var i = 0; i < args.Length; i++)
            {
                var arg = args[i];
                if (arg.Equals("--help", StringComparison.OrdinalIgnoreCase) || arg == "-h")
                {
                    return options with { ShowHelp = true };
                }

                if (arg.Equals("--redis", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                {
                    options = options with { RedisConnectionString = args[++i] };
                    continue;
                }

                if (arg.Equals("--url", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                {
                    options = options with { BaseUrl = args[++i] };
                    continue;
                }

                if (arg.Equals("--sample", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                {
                    options = options with { Sample = args[++i] };
                    continue;
                }
            }

            return options;
        }

        public static void PrintUsage()
        {
            Console.WriteLine("Elf.AccessRateLimit.Tests usage:");
            Console.WriteLine("  --redis <connection>   Redis connection string (default: localhost:6379)");
            Console.WriteLine("  --url <baseUrl>         Base URL (default: http://127.0.0.1:5055)");
            Console.WriteLine("  --sample <all|basic|keys|escalation>");
            Console.WriteLine("  --help                  Show help");
        }
    }

    private sealed class ResponseSnapshot
    {
        public HttpStatusCode StatusCode { get; init; }

        public int? Limit { get; init; }

        public int? Remaining { get; init; }

        public int? RetryAfterSeconds { get; init; }

        public static ResponseSnapshot From(HttpResponseMessage response)
        {
            int? limit = null;
            int? remaining = null;
            int? retryAfter = null;

            if (response.Headers.TryGetValues("X-RateLimit-Limit", out var limitValues))
            {
                if (int.TryParse(limitValues.FirstOrDefault(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
                {
                    limit = parsed;
                }
            }

            if (response.Headers.TryGetValues("X-RateLimit-Remaining", out var remainingValues))
            {
                if (int.TryParse(remainingValues.FirstOrDefault(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
                {
                    remaining = parsed;
                }
            }

            if (response.Headers.TryGetValues("Retry-After", out var retryValues))
            {
                if (int.TryParse(retryValues.FirstOrDefault(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
                {
                    retryAfter = parsed;
                }
            }

            return new ResponseSnapshot
            {
                StatusCode = response.StatusCode,
                Limit = limit,
                Remaining = remaining,
                RetryAfterSeconds = retryAfter
            };
        }
    }
}
