using System.Globalization;
using StackExchange.Redis;

namespace Elf.AccessRateLimit;

internal sealed class RedisRateLimitStore : IAccessRateLimitStore
{
    // Lua script performs atomic token-bucket evaluation and penalty escalation.
    private static readonly LuaScript RateLimitScript = LuaScript.Prepare(@"
local blockTtl = redis.call('PTTL', KEYS[2])
if blockTtl > 0 then
  local retryAfter = math.ceil(blockTtl / 1000)
  return {0, -1, 1, retryAfter, 0, 0}
end

local nowData = redis.call('TIME')
local now = tonumber(nowData[1]) + (tonumber(nowData[2]) / 1000000)
local capacity = tonumber(ARGV[1])
local refillRate = tonumber(ARGV[2])
local cost = tonumber(ARGV[3])
local windowSeconds = tonumber(ARGV[4])

local data = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(data[1])
local ts = tonumber(data[2])
if tokens == nil then tokens = capacity end
if ts == nil then ts = now end

local delta = now - ts
if delta < 0 then delta = 0 end

local filled = tokens + (delta * refillRate)
if filled > capacity then filled = capacity end

local allowed = 0
local remaining = filled
if filled >= cost then
  allowed = 1
  remaining = filled - cost
end

redis.call('HMSET', KEYS[1], 'tokens', remaining, 'ts', now)
local ttl = math.ceil(windowSeconds * 2)
if ttl < 1 then ttl = 1 end
redis.call('EXPIRE', KEYS[1], ttl)

local resetAfter = 0
if refillRate > 0 then
  resetAfter = math.ceil((capacity - remaining) / refillRate)
end

if allowed == 1 then
  return {1, remaining, 0, 0, resetAfter, 0}
end

local violations = 0
local violationWindow = tonumber(ARGV[5])
local penaltyCount = tonumber(ARGV[6])
if (penaltyCount ~= nil and penaltyCount > 0) or (violationWindow ~= nil and violationWindow > 0) then
  violations = redis.call('INCR', KEYS[3])
  if violationWindow ~= nil and violationWindow > 0 then
    redis.call('EXPIRE', KEYS[3], violationWindow)
  end
end

local penalty = 0
if penaltyCount ~= nil and penaltyCount > 0 then
  local index = violations
  if index > penaltyCount then index = penaltyCount end
  penalty = tonumber(ARGV[6 + index]) or 0
end

if penalty > 0 then
  redis.call('SETEX', KEYS[2], penalty, '1')
end

local retryAfter = penalty
if retryAfter == 0 then
  if refillRate > 0 then
    retryAfter = math.ceil((cost - remaining) / refillRate)
  else
    retryAfter = windowSeconds
  end
end

return {0, remaining, penalty > 0 and 1 or 0, retryAfter, resetAfter, violations}
");

    private readonly IConnectionMultiplexer _connectionMultiplexer;

    public RedisRateLimitStore(IConnectionMultiplexer connectionMultiplexer)
    {
        _connectionMultiplexer = connectionMultiplexer ?? throw new ArgumentNullException(nameof(connectionMultiplexer));
    }

    public async Task<AccessRateLimitStoreResult> EvaluateAsync(AccessRateLimitStoreRequest request, CancellationToken cancellationToken)
    {
        var database = _connectionMultiplexer.GetDatabase();

        // Compute rates and penalties for the script arguments.
        var windowSeconds = request.Window.TotalSeconds;
        var refillRate = request.Capacity / windowSeconds;
        var penaltySeconds = request.Penalty.Enabled ? request.Penalty.Penalties : new List<TimeSpan>();
        var penaltyCount = penaltySeconds.Count;

        // Pass numeric values as strings to avoid locale issues in Lua.
        var args = new List<RedisValue>
        {
            request.Capacity,
            refillRate.ToString("0.########", CultureInfo.InvariantCulture),
            request.Cost,
            windowSeconds.ToString("0.########", CultureInfo.InvariantCulture),
            request.Penalty.Enabled ? request.Penalty.ViolationWindow.TotalSeconds.ToString("0.########", CultureInfo.InvariantCulture) : "0",
            penaltyCount
        };

        foreach (var penalty in penaltySeconds)
        {
            args.Add(penalty.TotalSeconds.ToString("0.########", CultureInfo.InvariantCulture));
        }

        // Execute the script with keys and arguments.
        var keys = new RedisKey[] { request.BucketKey, request.BlockKey, request.ViolationKey };
        var result = (RedisResult[]?)await database.ScriptEvaluateAsync(
            RateLimitScript.ExecutableScript,
            keys,
            args.ToArray()).ConfigureAwait(false);
        if (result == null || result.Length < 6)
        {
            throw new InvalidOperationException("Unexpected Redis rate limit response.");
        }

        var allowed = long.Parse(result[0].ToString() ?? "0", CultureInfo.InvariantCulture) == 1;
        var remaining = double.Parse(result[1].ToString() ?? "0", CultureInfo.InvariantCulture);
        var blocked = long.Parse(result[2].ToString() ?? "0", CultureInfo.InvariantCulture) == 1;
        var retryAfter = (int)long.Parse(result[3].ToString() ?? "0", CultureInfo.InvariantCulture);
        var resetAfter = (int)long.Parse(result[4].ToString() ?? "0", CultureInfo.InvariantCulture);
        var violations = long.Parse(result[5].ToString() ?? "0", CultureInfo.InvariantCulture);

        return new AccessRateLimitStoreResult(
            allowed,
            blocked,
            remaining,
            retryAfter,
            resetAfter,
            violations);
    }
}
