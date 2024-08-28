-- Copyright 2023 SmartThings
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

local capabilities = require "st.capabilities"
local clusters = require "st.matter.clusters"
local log = require "log"

--OvenMode is currently not available in any of lua_libs releases
clusters.OvenMode = require "OvenMode"

local COMPONENT_TO_ENDPOINT_MAP = "__component_to_endpoint_map"
local SUPPORTED_OVEN_MODES_MAP = "__supported_oven_modes_map_key_"
local SUPPORTED_TEMPERATURE_LEVELS_MAP = "__supported_temperature_levels_map"

local OVEN_DEVICE_ID = 0x007B
local COOK_SURFACE_DEVICE_TYPE_ID = 0x0077
local COOK_TOP_DEVICE_TYPE_ID = 0x0078
local TCC_DEVICE_TYPE_ID = 0x0071

local function get_endpoints_for_dt(device, device_type)
  local endpoints = {}
  for _, ep in ipairs(device.endpoints) do
    for _, dt in ipairs(ep.device_types) do
      if dt.device_type_id == device_type then
        table.insert(endpoints, ep.endpoint_id)
        break
      end
    end
  end
  table.sort(endpoints)
  return endpoints
end

local function endpoint_to_component(device, ep)
  local map = device:get_field(COMPONENT_TO_ENDPOINT_MAP) or {}
  for component, endpoint in pairs(map) do
    if endpoint == ep then
      return component
    end
  end
  return "main"
end

local function component_to_endpoint(device, component)
  local map = device:get_field(COMPONENT_TO_ENDPOINT_MAP) or {}
  if map[component] then
    return map[component]
  end
  return device.MATTER_DEFAULT_ENDPOINT
end

-- Lifecycle Handlers --
local function is_oven_device(opts, driver, device)
  local oven_eps = get_endpoints_for_dt(device, OVEN_DEVICE_ID)
  if #oven_eps > 0 then
    return true
  end
  return false
end

local function device_init(driver, device)
  device:subscribe()
  device:set_endpoint_to_component_fn(endpoint_to_component)
  device:set_component_to_endpoint_fn(component_to_endpoint)
end

local function device_added(driver, device)
  -- We assume the following endpoint structure of oven device for now
  local cook_surface_endpoints = get_endpoints_for_dt(device, COOK_SURFACE_DEVICE_TYPE_ID)
  local cook_top_endpoint = get_endpoints_for_dt(device, COOK_TOP_DEVICE_TYPE_ID)[1] or device.MATTER_DEFAULT_ENDPOINT
  local tcc_endpoints = get_endpoints_for_dt(device, TCC_DEVICE_TYPE_ID)
  local componentToEndpointMap = {
    ["tccOne"] = tcc_endpoints[1],
    ["tccTwo"] = tcc_endpoints[2],
    ["cookTop"] = cook_top_endpoint,
    ["cookSurfaceOne"] = cook_surface_endpoints[1],
    ["cookSurfaceTwo"] = cook_surface_endpoints[2]
  }
  device:set_field(COMPONENT_TO_ENDPOINT_MAP, componentToEndpointMap, { persist = true })
end

-- Matter Handlers --
local function oven_supported_modes_attr_handler(driver, device, ib, response)
  local supportedOvenModesMap = device:get_field(SUPPORTED_OVEN_MODES_MAP) or {}
  local supportedOvenModes = {}
  for _, mode in ipairs(ib.data.elements) do
    clusters.OvenMode.types.ModeOptionStruct:augment_type(mode)
    local modeLabel = mode.elements.label.value
    log.info_with("Inserting supported oven mode: "..modeLabel)
    table.insert(supportedOvenModes, modeLabel)
  end
  supportedOvenModesMap[string.format(ib.endpoint_id)] = supportedOvenModes
  device:set_field(SUPPORTED_OVEN_MODES_MAP, supportedOvenModesMap, {persist = true})
  local event = capabilities.mode.supportedModes(supportedOvenModes, {visibility = {displayed = false}})
  device:emit_event_for_endpoint(ib.endpoint_id, event)
end

local function oven_mode_attr_handler(driver, device, ib, response)
  log.info_with({ hub_logs = true },
    string.format("oven_mode_attr_handler currentMode: %s", ib.data.value))

  local supportedOvenModesMap = device:get_field(SUPPORTED_OVEN_MODES_MAP) or {}
  local supportedOvenModes = supportedOvenModesMap[string.format(ib.endpoint_id)] or {}
  local currentMode = ib.data.value
  if supportedOvenModes[currentMode + 1] then
    local mode = supportedOvenModes[currentMode + 1]
    device:emit_event_for_endpoint(ib.endpoint_id, capabilities.mode.mode(mode, {state_change = true}))
    return
  end
  log.warn_with({hub_logs=true}, "oven_mode_attr_handler received unsupported mode for endpoint"..ib.endpoint_id)
end

local function temp_measure_value_attr_handler(driver, device, ib, response)
  local ep = ib.endpoint_id
  if not device:supports_capability(capabilities.temperatureMeasurement, endpoint_to_component(device, ep)) then
    device.log.info_with({ hub_logs = true }, string.format("EP(%d) does not support temperature measurement", ep))
    return
  end
  local temp = 0
  local unit = "C"
  if ib.data.value ~= nil then
    temp = ib.data.value / 100.0
  end
  device:emit_event_for_endpoint(ib.endpoint_id, capabilities.temperatureMeasurement.temperature({ value = temp, unit = unit }))
end

local function selected_temperature_level_attr_handler(driver, device, ib, response)
  local ep = ib.endpoint_id
  if not device:supports_capability(capabilities.temperatureLevel, endpoint_to_component(device, ep)) then
    device.log.info_with({ hub_logs = true }, string.format("EP(%d) does not support temperature level", ep))
    return
  end
  local temperatureLevel = ib.data.value
  local supportedTemperatureLevelsMap = device:get_field(SUPPORTED_TEMPERATURE_LEVELS_MAP)
  if not supportedTemperatureLevelsMap then
    return
  end
  local supportedTemperatureLevels = supportedTemperatureLevelsMap[ib.endpoint_id]
  for i, tempLevel in ipairs(supportedTemperatureLevels) do
    device.log.info(string.format("selected_temperature_level_attr_handler: %d, %s", i, tempLevel))
    if i - 1 == temperatureLevel then
      device:emit_event_for_endpoint(ib.endpoint_id, capabilities.temperatureLevel.temperatureLevel(tempLevel))
      break
    end
  end
end

local function supported_temperature_levels_attr_handler(driver, device, ib, response)
  local ep = ib.endpoint_id
  if not device:supports_capability(capabilities.temperatureLevel, endpoint_to_component(device, ep)) then
    device.log.info_with({ hub_logs = true }, string.format("EP(%d) does not support temperature level", ep))
    return
  end

  local supportedTemperatureLevelsMap = device:get_field(SUPPORTED_TEMPERATURE_LEVELS_MAP) or {}
  local supportedTemperatureLevels = {}
  for _, tempLevel in ipairs(ib.data.elements) do
    device.log.info(string.format("supported_temperature_levels_attr_handler: %s", tempLevel.value))
    table.insert(supportedTemperatureLevels, tempLevel.value)
  end
  for ep = 1, ib.endpoint_id - 1 do
    if not supportedTemperatureLevelsMap[ep] then
      device.log.info(string.format("supportedTemperatureLevelsMap[%d] is nil", ep))
      supportedTemperatureLevelsMap[ep] = {"Nothing"}
    end
  end
  supportedTemperatureLevelsMap[ib.endpoint_id] = supportedTemperatureLevels
  device:set_field(SUPPORTED_TEMPERATURE_LEVELS_MAP, supportedTemperatureLevelsMap, { persist = true })
  local event = capabilities.temperatureLevel.supportedTemperatureLevels(supportedTemperatureLevels, {visibility = {displayed = false}})
  device:emit_event_for_endpoint(ib.endpoint_id, event)
end

-- Capability Handlers --
local function handle_oven_mode(driver, device, cmd)
  log.info_with({ hub_logs = true }, string.format("handle_oven_mode mode: %s", cmd.args.mode))
  local ep = component_to_endpoint(device, cmd.component)
  local supportedOvenModesMap = device:get_field(SUPPORTED_OVEN_MODES_MAP) or {}
  local supportedOvenModes = supportedOvenModesMap[string.format(ep)] or {}
  for i, mode in ipairs(supportedOvenModes) do
    if cmd.args.mode == mode then
      device:send(clusters.OvenMode.commands.ChangeToMode(device, ep, i - 1))
      return
    end
  end
  log.warn_with({hub_logs=true}, "handle_oven_mode received unsupported mode: ".." for endpoint: "..ep)
end

local function handle_temperature_level(driver, device, cmd)
  local ep = component_to_endpoint(device, cmd.component)
  local supportedTemperatureLevelsMap = device:get_field(SUPPORTED_TEMPERATURE_LEVELS_MAP)
  if not supportedTemperatureLevelsMap then
    return
  end
  local supportedTemperatureLevels = supportedTemperatureLevelsMap[ep]
  for i, tempLevel in ipairs(supportedTemperatureLevels) do
    if cmd.args.temperatureLevel == tempLevel then
      device:send(clusters.TemperatureControl.commands.SetTemperature(device, ep, nil, i - 1))
      return
    end
  end
end

local matter_oven_handler = {
  NAME = "matter-oven",
  lifecycle_handlers = {
    init = device_init,
    added = device_added,
  },
  matter_handlers = {
    attr = {
      [clusters.OvenMode.ID] = {
        [clusters.OvenMode.attributes.SupportedModes.ID] = oven_supported_modes_attr_handler,
        [clusters.OvenMode.attributes.CurrentMode.ID] = oven_mode_attr_handler,
      },
      [clusters.TemperatureControl.ID] = {
        [clusters.TemperatureControl.attributes.SelectedTemperatureLevel.ID] = selected_temperature_level_attr_handler,
        [clusters.TemperatureControl.attributes.SupportedTemperatureLevels.ID] = supported_temperature_levels_attr_handler,
      },
      [clusters.TemperatureMeasurement.ID] = {
        [clusters.TemperatureMeasurement.attributes.MeasuredValue.ID] = temp_measure_value_attr_handler,
      }
    },
  },
  capability_handlers = {
    [capabilities.mode.ID] = {
      [capabilities.mode.commands.setMode.NAME] = handle_oven_mode,
    },
    [capabilities.temperatureLevel.ID] = {
      [capabilities.temperatureLevel.commands.setTemperatureLevel.NAME] = handle_temperature_level,
    },
  },
  can_handle = is_oven_device,
}

return matter_oven_handler