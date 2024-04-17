local cosock = require "cosock"
local log = require "logjam"
local json = require "st.json"
local st_utils = require "st.utils"

local Discovery = require "disco"
local EventSource = require "lunchbox.sse.eventsource"
local Fields = require "fields"
local HueApi = require "hue.api"
local StrayDeviceHelper = require "stray_device_helper"

local attribute_emitters = require "handlers.attribute_emitters"
local command_handlers = require "handlers.commands"
local lifecycle_handlers = require "handlers.lifecycle_handlers"

local lunchbox_util = require "lunchbox.util"
local utils = require "utils"

---@class hue_bridge_utils
local hue_bridge_utils = {}

---@param driver HueDriver
---@param bridge_device HueBridgeDevice
---@param bridge_url string
---@param api_key string
function hue_bridge_utils.do_bridge_network_init(driver, bridge_device, bridge_url, api_key)
  if not bridge_device:get_field(Fields.EVENT_SOURCE) then
    log.info_with({ hub_logs = true }, "Creating SSE EventSource for bridge " ..
      (bridge_device.label or bridge_device.device_network_id or bridge_device.id or "unknown bridge"))
    local url_table = lunchbox_util.force_url_table(bridge_url .. "/eventstream/clip/v2")
    local eventsource = EventSource.new(
      url_table,
      { [HueApi.APPLICATION_KEY_HEADER] = api_key },
      nil
    )

    eventsource.onopen = function(msg)
      log.info_with({ hub_logs = true },
        string.format("Event Source Connection for Hue Bridge \"%s\" established, marking online", bridge_device.label))
      bridge_device:online()

      local bridge_api = bridge_device:get_field(Fields.BRIDGE_API) --[[@as PhilipsHueApi]]
      cosock.spawn(function()
        -- We don't want to do a scan if we're already in a discovery loop,
        -- because the event source connection will open if a bridge is discovered
        -- and we'll effectively be scanning twice.
        -- Two scans that find the same device close together can emit events close enough
        -- together that the dedupe logic at the cloud layer will get bypassed and lead to
        -- duplicate device records.
        if not Discovery.discovery_active then
          Discovery.scan_bridge_and_update_devices(driver, bridge_device:get_field(Fields.BRIDGE_ID))
        end
        ---@type table<string,HueChildDevice>
        local child_device_map = {}
        local children = bridge_device:get_child_list()
        local _log = bridge_device.log or log
        _log.debug(string.format("Scanning connectivity of %s child devices", #children))
        for _, device_record in ipairs(children) do
          local hue_device_id = device_record:get_field(Fields.HUE_DEVICE_ID)
          if hue_device_id ~= nil then
            child_device_map[hue_device_id] = device_record
          end
        end

        local scanned = false
        local connectivity_status, rest_err

        while true do
          if scanned then break end
          connectivity_status, rest_err = bridge_api:get_connectivity_status()
          if rest_err ~= nil or not connectivity_status then
            log.error(string.format("Couldn't query Hue Bridge %s for zigbee connectivity status for child devices: %s",
              bridge_device.label, st_utils.stringify_table(rest_err, "Rest Error", true)))
            goto continue
          end

          if connectivity_status.errors and #connectivity_status.errors > 0 then
            log.error(
              string.format(
                "Hue Bridge %s replied with the following error message(s) " ..
                "when querying child device connectivity status:",
                bridge_device.label
              )
            )
            for idx, err in ipairs(connectivity_status.errors) do
              log.error(string.format("--- %s", st_utils.stringify_table(err, string.format("Error %s:", idx), true)))
            end
            goto continue
          end

          if connectivity_status.data and #connectivity_status.data > 0 then
            scanned = true
            for _, status in ipairs(connectivity_status.data) do
              local hue_device_id = (status.owner and status.owner.rid) or ""
              log.trace(string.format("Checking connectivity status for device resource id %s", hue_device_id))
              local child_device = child_device_map[hue_device_id]
              if child_device then
                if not child_device.id then
                  child_device_map[hue_device_id] = nil
                else
                  if status.status == "connected" then
                    child_device.log.info_with({ hub_logs = true }, "Marking Online after SSE Reconnect")
                    child_device:online()
                    child_device:set_field(Fields.IS_ONLINE, true)
                  elseif status.status == "connectivity_issue" then
                    child_device.log.info_with({ hub_logs = true }, "Marking Offline after SSE Reconnect")
                    child_device:set_field(Fields.IS_ONLINE, false)
                    child_device:offline()
                  end
                end
              end
            end
          end

          ::continue::
        end
      end, string.format("Hue Bridge %s Zigbee Scan Task", bridge_device.label))
    end

    eventsource.onerror = function()
      log.error_with({ hub_logs = true }, string.format("Hue Bridge \"%s\" Event Source Error", bridge_device.label))

      for _, device_record in ipairs(bridge_device:get_child_list()) do
        device_record:set_field(Fields.IS_ONLINE, false)
        device_record:offline()
      end

      bridge_device:offline()
    end

    eventsource.onmessage = function(msg)
      if msg and msg.data then
        local json_result = table.pack(pcall(json.decode, msg.data))
        local success = table.remove(json_result, 1)
        ---@type HueSseEvent[], string?
        local events, err = table.unpack(json_result, 1, json_result.n)

        if not success then
          log.error_with({ hub_logs = true, },
            "Couldn't decode JSON in SSE callback: " .. (events or "unexpected nil from pcall catch"))
          return
        end

        if err ~= nil then
          log.error_with({ hub_logs = true }, "JSON Parsing Error: " .. err)
          return
        end

        for _, event in ipairs(events) do
          if event.type == "update" then
            for _, update_data in ipairs(event.data) do
              log.debug(true, "Received update event with type " .. update_data.type)
              local resource_ids = {}
              if update_data.type == "zigbee_connectivity" and update_data.owner ~= nil then
                for rid, rtype in pairs(driver.services_for_device_rid[update_data.owner.rid] or {}) do
                  if driver.hue_identifier_to_device_record[rid] then
                    log.debug(string.format("Adding RID %s to resource_ids", rid))
                    table.insert(resource_ids, rid)
                  end
                end
              else
                --- for a regular message from a light doing something normal,
                --- you get the resource id of the light service for that device in
                --- the data field
                table.insert(resource_ids, update_data.id)
              end
              for _, resource_id in ipairs(resource_ids) do
                log.debug(true, string.format("Looking for device record for %s", resource_id))
                local child_device = driver.hue_identifier_to_device_record[resource_id]
                if child_device ~= nil and child_device.id ~= nil then
                  if update_data.type == "zigbee_connectivity" then
                    log.debug("emitting event for zigbee connectivity")
                    attribute_emitters.connectivity_update(child_device, update_data)
                  else
                    local device_type = utils.determine_device_type(child_device)
                    log.debug(true, st_utils.stringify_table({device_type = device_type, update_data}, "updating", true))
                    attribute_emitters.emitter_for_device_type(device_type)(child_device, update_data)
                  end
                end
              end
            end
          elseif event.type == "delete" then
            for _, delete_data in ipairs(event.data) do
              if delete_data.type == "light" then
                local resource_id = delete_data.id
                local child_device = driver.hue_identifier_to_device_record[resource_id]
                if child_device ~= nil and child_device.id ~= nil then
                  log.info(
                    string.format(
                      "Light device \"%s\" was deleted from hue bridge %s",
                      (child_device.label or child_device.id or "unknown device"),
                      (bridge_device.label or bridge_device.device_network_id or bridge_device.id or "unknown bridge")
                    )
                  )
                  child_device.log.trace("Attempting to delete Device UUID " .. tostring(child_device.id))
                  driver:do_hue_child_delete(child_device)
                end
              end
            end
          elseif event.type == "add" then
            for _, add_data in ipairs(event.data) do
              if add_data.type == "light" and add_data.owner and add_data.owner.rtype == "device" then
                ---@cast add_data HueLightInfo
                log.info(
                  string.format(
                    "New light added to Hue Bridge \"%s\", light properties: \"%s\"",
                    bridge_device.label, json.encode(add_data)
                  )
                )

                cosock.spawn(function()
                  local hue_api = bridge_device:get_field(Fields.BRIDGE_API) --[[@as PhilipsHueApi]]
                  if hue_api == nil then
                    local _log = bridge_device.log or log
                    _log.warn("No Hue API instance available for new light event.")
                    return
                  end

                  local hue_device_rid = add_data.owner.rid
                  local rest_resp, rest_err = hue_api:get_device_by_id(hue_device_rid)

                  if rest_err ~= nil then
                    log.error(
                      string.format(
                        "Error getting device information for new light \"%s\" with device RID %s: %s",
                        add_data.metadata.name,
                        hue_device_rid,
                        st_utils.stringify_table(rest_err)
                      )
                    )
                    return
                  end

                  if rest_resp == nil then
                    log.error("REST Response while handling New Light Event unexpectedly nil without error message")
                    return
                  end

                  if rest_resp.errors and #rest_resp.errors > 0 then
                    for _, hue_error in ipairs(rest_resp.errors) do
                      log.error_with({ hub_logs = true }, "Error in Hue API response: " .. hue_error.description)
                    end
                    return
                  end

                  local new_device_info = nil
                  for _, hue_device in ipairs(rest_resp.data or {}) do
                    for _, svc_info in ipairs(hue_device.services or {}) do
                      if svc_info.rtype == "light" and svc_info.rid == add_data.id then
                        new_device_info = hue_device
                        break
                      end
                    end
                    if new_device_info ~= nil then break end
                  end

                  if new_device_info == nil then
                    log.warn(
                    "Couldn't get all device info for new light, unable to join. Try using Scan Nearby to find new Hue lights.")
                    return
                  end

                  log.info(
                    string.format(
                      "Adding light \"%s\"",
                      add_data.metadata.name
                    )
                  )

                  local profile_ref

                  if add_data.color then
                    if add_data.color_temperature then
                      profile_ref = "white-and-color-ambiance"
                    else
                      profile_ref = "legacy-color"
                    end
                  elseif add_data.color_temperature then
                    profile_ref = "white-ambiance" -- all color temp products support `white` (dimming)
                  elseif add_data.dimming then
                    profile_ref = "white"          -- `white` refers to dimmable and includes filament bulbs
                  else
                    log.warn(
                      string.format(
                        "Light resource [%s] does not seem to be A White/White-Ambiance/White-Color-Ambiance device, currently unsupported"
                        ,
                        add_data.id
                      )
                    )
                    return
                  end

                  local create_device_msg = {
                    type = "EDGE_CHILD",
                    label = add_data.metadata.name,
                    vendor_provided_label = new_device_info.product_data.product_name,
                    profile = profile_ref,
                    manufacturer = new_device_info.product_data.manufacturer_name,
                    model = new_device_info.product_data.model_id,
                    parent_device_id = bridge_device.id,
                    parent_assigned_child_key = string.format("%s:%s", add_data.type, add_data.id)
                  }

                  Discovery.device_state_disco_cache[add_data.id] = {
                    hue_provided_name = add_data.metadata.name,
                    id = add_data.id,
                    on = add_data.on,
                    color = add_data.color,
                    dimming = add_data.dimming,
                    color_temperature = add_data.color_temperature,
                    mode = add_data.mode,
                    parent_device_id = bridge_device.id,
                    hue_device_id = add_data.owner.rid,
                    hue_device_data = new_device_info
                  }

                  driver:try_create_device(create_device_msg)
                end, "New Device Event Task")
              end
            end
          end
        end
      end
    end

    bridge_device:set_field(Fields.EVENT_SOURCE, eventsource, { persist = false })
  end
  bridge_device:set_field(Fields._INIT, true, { persist = false })
  local ids_to_remove = {}
  for id, device in ipairs(driver._devices_pending_refresh) do
    local bridge_id = device.parent_device_id or bridge_device:get_field(Fields.PARENT_DEVICE_ID)
    if bridge_id == bridge_device.id then
      table.insert(ids_to_remove, id)
      command_handlers.refresh_handler(driver, device)
    end
  end
  for _, id in ipairs(ids_to_remove) do
    driver._devices_pending_refresh[id] = nil
  end
  driver.stray_device_tx:send({
    type = StrayDeviceHelper.MessageTypes.FoundBridge,
    driver = driver,
    device = bridge_device
  })
end

---@param driver HueDriver
---@param bridge_info table
---@param bridge_device HueBridgeDevice
function hue_bridge_utils.update_bridge_fields_from_info(driver, bridge_info, bridge_device)
  local bridge_ip = bridge_info.ip
  local device_bridge_id = bridge_device.device_network_id

  if bridge_device:get_field(Fields._REFRESH_AFTER_INIT) == nil then
    bridge_device:set_field(Fields._REFRESH_AFTER_INIT, true, { persist = true })
  end

  bridge_device:set_field(Fields.DEVICE_TYPE, "bridge", { persist = true })
  bridge_device:set_field(Fields.MODEL_ID, bridge_info.modelid, { persist = true })
  bridge_device:set_field(Fields.BRIDGE_ID, device_bridge_id, { persist = true })
  bridge_device:set_field(Fields.BRIDGE_SW_VERSION, tonumber(bridge_info.swversion or "0", 10), { persist = true })

  if Discovery.api_keys[device_bridge_id] then
    bridge_device:set_field(HueApi.APPLICATION_KEY_HEADER, Discovery.api_keys[device_bridge_id], { persist = true })
    driver.api_key_to_bridge_id[Discovery.api_keys[device_bridge_id]] = device_bridge_id
  end
  bridge_device:set_field(Fields.IPV4, bridge_ip, { persist = true })
end

---@param driver HueDriver
---@param device HueBridgeDevice
function hue_bridge_utils.spawn_bridge_add_api_key_task(driver, device)
  local device_bridge_id = device.device_network_id
  cosock.spawn(function()
    -- 30 seconds is the typical UX for waiting to hit the link button in the Hue ecosystem
    local timeout_time = cosock.socket.gettime() + 30

    -- we pre-declare these variables in the outer scope so that our gotos work.
    -- a sad day that we need these gotos.
    local api_key_response, err, api_key, bridge_info, bridge_ip, _
    repeat
      local time_remaining = math.max(0, timeout_time - cosock.socket.gettime())
      if time_remaining == 0 then
        local _log = device.log or log
        _log.error_with({ hub_logs = true },
          string.format(
            "Link button not pressed or API key not received for bridge \"%s\" after 30 seconds, sleeping then trying again in a few minutes.",
            device.label
          )
        )
        cosock.socket.sleep(120)                    -- two minutes
        timeout_time = cosock.socket.gettime() + 30 -- refresh timeout time
        goto continue
      end

      if not driver.datastore.bridge_netinfo[device_bridge_id] then
        goto continue
      end

      bridge_info = driver.datastore.bridge_netinfo[device_bridge_id]
      bridge_ip = bridge_info.ip

      api_key_response, err, _ = HueApi.request_api_key(
        bridge_ip,
        utils.labeled_socket_builder((device.label or device.device_network_id or device.id or "unknown bridge"))
      )

      if err ~= nil or not api_key_response then
        log.warn("Error while trying to request Bridge API Key: ", err)
        goto continue
      end

      for _, item in ipairs(api_key_response) do
        if item.error ~= nil then
          log.warn("Error paylod in bridge API key response: " .. item.error.description)
          goto continue
        end

        api_key = item.success.username
      end

      ::continue::
      -- don't hammer the bridge since we're waiting for the user to hit the link button
      if api_key == nil then cosock.socket.sleep(2) end
    until api_key ~= nil

    if not api_key then
      log.error_with({ hub_logs = true }, "Link button not pressed or API key not received for bridge " ..
        (device.label or device.device_network_id or device.id or "unknown"))
      return
    end

    Discovery.api_keys[device_bridge_id] = api_key
    lifecycle_handlers.initialize_device(driver, device)
  end, "Hue Bridge Background Join Task")
end

return hue_bridge_utils
