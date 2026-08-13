-- Consts
local EVT_MONITOR = "monitor"
local EVT_LEARN = "learn"
local DIRECTION_INBOUND = "inbound"
local MSG_MONITOR_PREFIX = "^dry%-run:"
local MSG_LEARN = "connection complete"

local function has_empty_field(record, key)
  local value = record[key]
  return value == nil or tostring(value) == ""
end

local function extract_port(address)
  if address == nil then
    return ""
  end
  local port = tostring(address):match(":(%d+)$")
  if port == nil then
    return ""
  end
  return port
end

local function to_monitor_event(timestamp, record)
  local proxy = record["proxy"] or {}
  local inbound = record["inbound"] or {}

  local out = {}
  out["evt.type"] = EVT_MONITOR
  -- `namespace/name` format
  -- e.g. "default/http-server-7bbf596dd9-8gs65"
  out["dst.namespaced_name"] = proxy["wl"] or ""
  -- `namespace/name` format if present, otherwise ""
  -- e.g. "default/deny-http-server-monitor"
  out["policy"] = record["policy"] or ""
  -- `ip:port` format
  out["src.addr"] = inbound["peer"] or ""
  out["body"] = EVT_MONITOR
  return 1, timestamp, out
end

local function to_learn_event(timestamp, record)
  -- We are only interested in inbound connections
  if record["direction"] ~= DIRECTION_INBOUND then
    return -1, timestamp, record
  end

  -- Skip learning when one endpoint is outside the mesh.
  -- These logs do not include both identities.
  if has_empty_field(record, "src.identity") or has_empty_field(record, "dst.identity") then
    return -1, timestamp, record
  end

  local out = {}
  out["evt.type"] = EVT_LEARN
  out["dst.name"] = record["dst.workload"]
  out["dst.namespace"] = record["dst.namespace"]
  out["dst.port"] = extract_port(record["dst.hbone_addr"])
  out["src.identity"] = record["src.identity"]
  -- we need a body field for the OpenTelemetry output plugin to work correctly
  -- todo! check if there is an alternative way
  out["body"] = EVT_LEARN
  return 1, timestamp, out
end

function to_otel(tag, timestamp, record)
  local message = record["message"]

  -- The log message should start with `dry-run:`
  if string.find(message or "", MSG_MONITOR_PREFIX) then
    return to_monitor_event(timestamp, record)
  end

  if record["message"] == MSG_LEARN then
    return to_learn_event(timestamp, record)
  end
  return -1, timestamp, record
end
