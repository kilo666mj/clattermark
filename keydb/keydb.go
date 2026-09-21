package keydb

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var ctx = context.Background()

var recordIncidentScript = redis.NewScript(`
local count = tonumber(redis.call('HGET', KEYS[1], 'count')) or 0
if count == 0 then
  redis.call('HSET', KEYS[1], 'first_seen_ms', ARGV[1], 'last_notified_count', 0)
end
count = redis.call('HINCRBY', KEYS[1], 'count', 1)
redis.call('HSET', KEYS[1], 'name', ARGV[2], 'title', ARGV[3], 'last_seen_ms', ARGV[1], 'sample', ARGV[4])
if ARGV[5] ~= '' then redis.call('HSET', KEYS[1], 'host:' .. ARGV[5], 1) end
if ARGV[6] ~= '' then redis.call('HSET', KEYS[1], 'process:' .. ARGV[6], 1) end
local last_notified = tonumber(redis.call('HGET', KEYS[1], 'last_notified_count')) or 0
local notify = 0
if last_notified == 0 or count - last_notified >= tonumber(ARGV[7]) then
  notify = 1
  redis.call('HSET', KEYS[1], 'last_notified_count', count)
end
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[8]) * 4)
redis.call('ZADD', KEYS[2], ARGV[1], ARGV[2])
return {redis.call('HGET', KEYS[1], 'first_seen_ms'), ARGV[1], count, notify}
`)

var releaseIncidentNotificationScript = redis.NewScript(`
local current = tonumber(redis.call('HGET', KEYS[1], 'last_notified_count')) or 0
if current == tonumber(ARGV[1]) then
  return redis.call('HSET', KEYS[1], 'last_notified_count', 0)
end
return 0
`)

var closeIncidentScript = redis.NewScript(`
local last_seen = tonumber(redis.call('HGET', KEYS[1], 'last_seen_ms'))
if not last_seen or last_seen > tonumber(ARGV[1]) then return 0 end
local fields = redis.call('HGETALL', KEYS[1])
local incident = {}
incident['hosts'] = {}
incident['processes'] = {}
for i = 1, #fields, 2 do
  local key = fields[i]
  local value = fields[i + 1]
  if string.sub(key, 1, 5) == 'host:' then
    table.insert(incident['hosts'], string.sub(key, 6))
  elseif string.sub(key, 1, 8) == 'process:' then
    table.insert(incident['processes'], string.sub(key, 9))
  else
    incident[key] = value
  end
end
redis.call('RPUSH', KEYS[3], cjson.encode(incident))
redis.call('LTRIM', KEYS[3], -tonumber(ARGV[2]), -1)
redis.call('DEL', KEYS[1])
redis.call('ZREM', KEYS[2], ARGV[3])
return 1
`)

type IncidentUpdate struct {
	FirstSeenMS int64
	LastSeenMS  int64
	Count       int
	Notify      bool
}

type Keydb struct {
	client *redis.Client
}

func (k *Keydb) GetJSON(key string, value any) (bool, error) {
	raw, err := k.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal([]byte(raw), value)
}

func (k *Keydb) SetJSON(key string, value any, ttl time.Duration) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return k.client.Set(ctx, key, raw, ttl).Err()
}

func (k *Keydb) EnqueueJSON(key string, value any, max int64) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	pipe := k.client.TxPipeline()
	pipe.RPush(ctx, key, raw)
	if max > 0 {
		pipe.LTrim(ctx, key, -max, -1)
	}
	_, err = pipe.Exec(ctx)
	return err
}

func (k *Keydb) PeekQueue(key string, max int64) ([]string, error) {
	if max <= 0 {
		return nil, nil
	}
	return k.client.LRange(ctx, key, 0, max-1).Result()
}

func (k *Keydb) DropQueue(key string, count int64) error {
	if count <= 0 {
		return nil
	}
	return k.client.LTrim(ctx, key, count, -1).Err()
}

func (k *Keydb) QueueLength(key string) (int64, error) {
	return k.client.LLen(ctx, key).Result()
}

func (k *Keydb) Close() error {
	return k.client.Close()
}

func New(host, password string) Keydb {
	return Keydb{
		client: redis.NewClient(&redis.Options{
			Addr:     host,
			Password: password,
			DB:       0,
		}),
	}
}

func (k *Keydb) GetDynExcludes() (map[string][]string, error) {
	var excludes map[string][]string
	val, err := k.client.Get(ctx, "excludes").Result()
	if err != nil {
		if err == redis.Nil {
			return map[string][]string{}, nil
		}
		return excludes, err
	}
	if val == "" {
		val = "{}"
	}
	err = json.Unmarshal([]byte(val), &excludes)
	if err != nil {
		return excludes, err
	}
	return excludes, nil
}

func (k *Keydb) SetDynExcludes(excludes map[string][]string) error {
	jsonExcludes, err := json.Marshal(excludes)
	if err != nil {
		return err
	}
	err = k.client.Set(ctx, "excludes", jsonExcludes, 0).Err()
	if err != nil {
		return err
	}
	return nil
}

// UpdateDynExclude atomically adds or removes one dynamic exclude and returns
// the canonical set stored in KeyDB. Concurrent API callers cannot overwrite
// each other's changes.
func (k *Keydb) UpdateDynExclude(excludeType, value string, add bool) (map[string][]string, bool, error) {
	var updated map[string][]string
	var changed bool
	const maxRetries = 16
	for attempt := 0; attempt < maxRetries; attempt++ {
		err := k.client.Watch(ctx, func(tx *redis.Tx) error {
			changed = false
			val, err := tx.Get(ctx, "excludes").Result()
			if err != nil && err != redis.Nil {
				return err
			}
			current := map[string][]string{}
			if err == nil && val != "" {
				if err := json.Unmarshal([]byte(val), &current); err != nil {
					return err
				}
			}

			values := current[excludeType]
			index := -1
			for i, existing := range values {
				if existing == value {
					index = i
					break
				}
			}
			if add && index < 0 {
				current[excludeType] = append(values, value)
				changed = true
			} else if !add && index >= 0 {
				current[excludeType] = append(values[:index], values[index+1:]...)
				if len(current[excludeType]) == 0 {
					delete(current, excludeType)
				}
				changed = true
			}

			if changed {
				raw, err := json.Marshal(current)
				if err != nil {
					return err
				}
				if _, err := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
					pipe.Set(ctx, "excludes", raw, 0)
					return nil
				}); err != nil {
					return err
				}
			}
			updated = current
			return nil
		}, "excludes")
		if err == redis.TxFailedErr {
			continue
		}
		return updated, changed, err
	}
	return nil, false, redis.TxFailedErr
}

// ReserveDedup atomically reserves a fingerprint for ttl. It returns false
// when another alert already owns the unexpired reservation.
func (k *Keydb) ReserveDedup(fingerprint string, ttl time.Duration) (bool, error) {
	return k.client.SetNX(ctx, "alert-dedup:"+fingerprint, "1", ttl).Result()
}

func (k *Keydb) ForgetDedup(fingerprint string) error {
	return k.client.Del(ctx, "alert-dedup:"+fingerprint).Err()
}

func (k *Keydb) RecordIncident(name, title, sample, host, process string, observed time.Time, quiet time.Duration, reminderEvery int) (IncidentUpdate, error) {
	if reminderEvery < 1 {
		reminderEvery = 25
	}
	key := "incident:v1:" + name
	result, err := recordIncidentScript.Run(ctx, k.client, []string{key, "incident:v1:active"},
		observed.UnixMilli(), name, title, sample, host, process, reminderEvery, quiet.Milliseconds()).Slice()
	if err != nil {
		return IncidentUpdate{}, err
	}
	values := make([]int64, len(result))
	for i, value := range result {
		values[i], err = toInt64(value)
		if err != nil {
			return IncidentUpdate{}, err
		}
	}
	return IncidentUpdate{FirstSeenMS: values[0], LastSeenMS: values[1], Count: int(values[2]), Notify: values[3] == 1}, nil
}

func (k *Keydb) ReleaseIncidentNotification(name string, count int) error {
	return releaseIncidentNotificationScript.Run(ctx, k.client, []string{"incident:v1:" + name}, count).Err()
}

func (k *Keydb) DueIncidents(cutoff time.Time, max int64) ([]string, error) {
	if max < 1 {
		max = 100
	}
	return k.client.ZRangeByScore(ctx, "incident:v1:active", &redis.ZRangeBy{
		Min: "-inf", Max: fmt.Sprint(cutoff.UnixMilli()), Offset: 0, Count: max,
	}).Result()
}

func (k *Keydb) CloseIncidentToOutbox(name string, cutoff time.Time, max int64) (bool, error) {
	if max < 1 {
		max = 1000
	}
	result, err := closeIncidentScript.Run(ctx, k.client,
		[]string{"incident:v1:" + name, "incident:v1:active", "incident:v1:recovery-outbox"},
		cutoff.UnixMilli(), max, name).Int()
	return result == 1, err
}

func toInt64(value any) (int64, error) {
	switch value := value.(type) {
	case int64:
		return value, nil
	case string:
		var parsed int64
		_, err := fmt.Sscan(value, &parsed)
		return parsed, err
	default:
		return 0, fmt.Errorf("unexpected redis integer type %T", value)
	}
}
