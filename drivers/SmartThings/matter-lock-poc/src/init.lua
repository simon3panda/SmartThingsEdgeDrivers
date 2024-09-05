-- Copyright 2022 SmartThings
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

local MatterDriver = require "st.matter.driver"
local clusters = require "st.matter.clusters"
local log = require "log"

local capabilities = require "st.capabilities"
local im = require "st.matter.interaction_model"
local lock_utils = require "lock_utils"

local INITIAL_COTA_INDEX = 1

local DoorLock = clusters.DoorLock

local lockWithPinID = "insideimage13541.newLockWithPin"
local lockWithPin = capabilities[lockWithPinID]

local lockAddUserID = "insideimage13541.newLockAddUser"
local lockAddUser = capabilities[lockAddUserID]
local lockModifyUserID = "insideimage13541.newLockModifyUser"
local lockModifyUser = capabilities[lockModifyUserID]
local lockClearUserID = "insideimage13541.newLockClearUser"
local lockClearUser = capabilities[lockClearUserID]
local lockGetUserID = "insideimage13541.newLockGetUser"
local lockGetUser = capabilities[lockGetUserID]

local lockAddPinID = "insideimage13541.newLockAddPin"
local lockAddPin = capabilities[lockAddPinID]
local lockModifyPinID = "insideimage13541.newLockModifyPin"
local lockModifyPin = capabilities[lockModifyPinID]
local lockClearPinID = "insideimage13541.newLockClearPin"
local lockClearPin = capabilities[lockClearPinID]
local lockGetPinID = "insideimage13541.newLockGetPin"
local lockGetPin = capabilities[lockGetPinID]

local lockAddWeekScheduleID = "insideimage13541.newLockAddWeekSchedule"
local lockAddWeekSchedule = capabilities[lockAddWeekScheduleID]
local lockClearWeekScheduleID = "insideimage13541.newLockClearWeekSchedule"
local lockClearWeekSchedule = capabilities[lockClearWeekScheduleID]
local lockGetWeekScheduleID = "insideimage13541.newLockGetWeekSchedule"
local lockGetWeekSchedule = capabilities[lockGetWeekScheduleID]

local lockAddYearScheduleID = "insideimage13541.newLockAddYearSchedule"
local lockAddYearSchedule = capabilities[lockAddYearScheduleID]
local lockClearYearScheduleID = "insideimage13541.newLockClearYearSchedule"
local lockClearYearSchedule = capabilities[lockClearYearScheduleID]
local lockGetYearScheduleID = "insideimage13541.newLockGetYearSchedule"
local lockGetYearSchedule = capabilities[lockGetYearScheduleID]

-- local lockStatusID = "insideimage13541.lockStatus1"
-- local lockStatus = capabilities[lockStatusID]
-- local lockStatusForPinID = "insideimage13541.lockStatusForPin1"
-- local lockStatusForPin = capabilities[lockStatusForPinID]
-- local lockStatusForUserID = "insideimage13541.lockStatusForUser3"
-- local lockStatusForUser = capabilities[lockStatusForUserID]

local USER_STATUS_MAP = {
  [0] = "",
  [1] = lockModifyUser.userStatus.occupiedEnabled.NAME,
  [2] = "",
  [3] = lockModifyUser.userStatus.occupiedDisabled.NAME
}

local USER_TYPE_MAP = {
  [0] = "unrestrictedUser",
  [1] = "yearDayScheduleUser",
  [2] = "weekDayScheduleUser",
  [3] = "programmingUser",
  [4] = "nonAccessUser",
  [5] = "forcedUser",
  [6] = "disposableUser",
  [7] = "expiringUser",
  [8] = "scheduleRestrictedUser",
  [9] = "remoteOnlyUser",
  [10] = "null"
}

local function numToBinStr(num)
	ret = ""
	while num ~= 1 and num ~= 0 do
		ret = tostring(num % 2)..ret
		num = math.modf(num / 2)
	end
	ret = tostring(num)..ret
	return ret
end










local function find_default_endpoint(device, cluster)
  local res = device.MATTER_DEFAULT_ENDPOINT
  local eps = device:get_endpoints(cluster)
  table.sort(eps)
  for _, v in ipairs(eps) do
    if v ~= 0 then --0 is the matter RootNode endpoint
      return v
    end
  end
  device.log.warn(string.format("Did not find default endpoint, will use endpoint %d instead", device.MATTER_DEFAULT_ENDPOINT))
  return res
end

local function component_to_endpoint(device, component_name)
  return find_default_endpoint(device, clusters.DoorLock.ID)
end

local function device_added(driver, device)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! device_added !!!!!!!!!!!!!"))
end

local function do_configure(driver, device)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! do_configure !!!!!!!!!!!!!"))
end

local function device_init(driver, device)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! device_init !!!!!!!!!!!!!"))
  device:set_component_to_endpoint_fn(component_to_endpoint)
  device:subscribe()

  local ep = device:component_to_endpoint(component_to_endpoint)
  device:emit_event(lockAddUser.userType.unrestrictedUser({state_change = true}))
  device:emit_event(lockModifyUser.userStatus.occupiedEnabled({state_change = true}))
  device:emit_event(lockModifyUser.userType.unrestrictedUser({state_change = true}))
  device:emit_event(lockAddPin.userType.unrestrictedUser({state_change = true}))

  -- User Data Hard coding
  local credential = {credential_type = 1, credential_index = 1}
  device:set_field(lock_utils.COMMAND_NAME, "addCredential", {persist = true})
  device:send(DoorLock.server.commands.SetCredential(device, ep, 0, credential, "\x30\x33\x35\x37\x39\x30", 1, nil, nil))
end














 -- Custom Driver for testing
-- Matter Handler
-- for Lock Status Capability
local function lock_state_handler(driver, device, ib, response)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! lock_state_handler: %s !!!!!!!!!!!!!", ib.data.value))
  local LockState = DoorLock.attributes.LockState
  if ib.data.value == LockState.NOT_FULLY_LOCKED then
    device:emit_event(capabilities.lock.lock.unknown({state_change = true}))
  elseif ib.data.value == LockState.LOCKED then
    device:emit_event(capabilities.lock.lock.locked({state_change = true}))
    device:emit_event(lockWithPin.lock.locked({state_change = true}))
  elseif ib.data.value == LockState.UNLOCKED then
    device:emit_event(capabilities.lock.lock.unlocked({state_change = true}))
    device:emit_event(lockWithPin.lock.unlocked({state_change = true}))
  elseif ib.data.value == LockState.UNLATCHED then
    device:emit_event(capabilities.lock.lock.locked({state_change = true}))
  else
    device:emit_event(capabilities.lock.lock.locked({state_change = true}))
  end
end

--------------------
-- Lock Operation --
--------------------
local function lock_op_event_handler(driver, device, ib, response)
  local fabricId = ib.data.elements.fabric_index
  local userIdx = ib.data.elements.user_index
  local event = ib.data.elements.lock_operation_type

  if fabricId ~= nil then
    fabricId = fabricId.value
  end
  if userIdx ~= nil then
    userIdx = userIdx.value
  end
  if event ~= nil then
    event = event.value
  end

  log.info_with({hub_logs=true}, string.format("fabricId: %s", fabricId))
  log.info_with({hub_logs=true}, string.format("userIdx: %s", userIdx))
  log.info_with({hub_logs=true}, string.format("event: %s", event))

  if event > 1 then
    return
  end

  device:emit_event(capabilities.lock.lock.data.userIndex(userIdx, {state_change = true}))
end

-- local function lock_op_err_event_handler(driver, device, ib, response)
--   local err = DoorLock.types.OperationErrorEnum
--   local event = ib.data.elements.operation_error
--   log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! lock_op_err_event_handler: %s !!!!!!!!!!!!!", event))
--   if event.value == err.UNSPECIFIED then
--     device:emit_event(lockStatus.lockOperationErrorEvent.unspecified())
--   elseif event.value == err.INVALID_CREDENTIAL then
--     device:emit_event(lockStatus.lockOperationErrorEvent.invalidCredential())
--   elseif event.value == err.DISABLED_USER_DENIED then
--     device:emit_event(lockStatus.lockOperationErrorEvent.disabledUserDenied())
--   elseif event.value == err.RESTRICTED then
--     device:emit_event(lockStatus.lockOperationErrorEvent.restricted())
--   elseif event.value == err.INSUFFICIENT_BATTERY then
--     device:emit_event(lockStatus.lockOperationErrorEvent.insufficientBattery())
--   else
--     device:emit_event(lockStatus.lockOperationErrorEvent.unspecified())
--   end
-- end

-- -- for Lock Status For Pin Capability
-- local function max_pin_code_len_handler(driver, device, ib, response)
--   log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! max_pin_code_len_handler: %d !!!!!!!!!!!!!", ib.data.value))
--   device:emit_event(lockStatusForPin.maxPinCodeLen(ib.data.value, {visibility = {displayed = false}}))
-- end

-- local function min_pin_code_len_handler(driver, device, ib, response)
--   log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! min_pin_code_len_handler: %d !!!!!!!!!!!!!", ib.data.value))
--   device:emit_event(lockStatusForPin.minPinCodeLen(ib.data.value, {visibility = {displayed = false}}))
-- end

-- local function num_pin_users_handler(driver, device, ib, response)
--   log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! min_pin_code_num_pin_users_handlerlen_handler: %d !!!!!!!!!!!!!", ib.data.value))
--   device:emit_event(lockStatusForPin.numberOfPinUsersSupported(ib.data.value, {visibility = {displayed = false}}))
-- end

-- local function wrong_code_entry_limit_handler(driver, device, ib, response)
--   log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! wrong_code_entry_limit_handler: %d !!!!!!!!!!!!!", ib.data.value))
--   device:emit_event(lockStatusForPin.wrongCodeEntryLimit(ib.data.value, {visibility = {displayed = false}}))
-- end

-- local function user_code_temporary_disable_time_handler(driver, device, ib, response)
--   log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! user_code_temporary_disable_time_handler: %d !!!!!!!!!!!!!", ib.data.value))
--   device:emit_event(lockStatusForPin.userCodeTemporaryDisableTime(ib.data.value, {visibility = {displayed = false}}))
-- end

-- local function require_remote_pin_handler(driver, device, ib, response)
--   log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! require_remote_pin_handler: %s !!!!!!!!!!!!!", ib.data.value))
--   if ib.data.value then
--     device:set_field(lock_utils.COTA_CRED, true, {persist = true})
--     device:emit_event(lockStatusForPin.requirePinForRemoteOperation.on())
--   else
--     device:set_field(lock_utils.COTA_CRED, false, {persist = true})
--     device:emit_event(lockStatusForPin.requirePinForRemoteOperation.off())
--   end
-- end

-- -- for Lock Status For User Capability
-- local function num_total_users_handler(driver, device, ib, response)
--   log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! num_total_users_handler: %d !!!!!!!!!!!!!", ib.data.value))
--   device:emit_event(lockStatusForUser.numberOfTotalUsersSupported(ib.data.value, {visibility = {displayed = false}}))
-- end

-- local function num_cred_handler(driver, device, ib, response)
--   log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! num_cred_handler: %d !!!!!!!!!!!!!", ib.data.value))
--   device:emit_event(lockStatusForUser.numberOfCredentialsSupportedPerUser(ib.data.value, {visibility = {displayed = false}}))
-- end

-- local function cred_rules_handler(driver, device, ib, response)
--   log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! cred_rules_handler: %d !!!!!!!!!!!!!", ib.data.value))
--   device:emit_event(lockStatusForUser.credentialRulesSupport(ib.data.value, {visibility = {displayed = false}}))
-- end

-- local function lock_user_change_event_handler(driver, device, ib, response)
--   local data_type_enum = DoorLock.types.LockDataTypeEnum
--   local operation_type_enum = DoorLock.types.DataOperationTypeEnum
--   local operation_source_enum = DoorLock.types.OperationSourceEnum
--   local elements = ib.data.elements
--   local data_type = elements.lock_data_type.value
--   local operation_type = elements.data_operation_type.value
--   local operation_source = elements.operation_source.value
--   log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! lock_user_change_event_handler: data_type: %s !!!!!!!!!!!!!", data_type))
--   log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! lock_user_change_event_handler: operation_type: %s !!!!!!!!!!!!!", operation_type))
--   log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! lock_user_change_event_handler: operation_source: %s !!!!!!!!!!!!!", operation_source))

--   if data_type == data_type_enum.UNSPECIFIED then
--     device:emit_event(lockStatusForUser.lockUserChangeDataType.unspecified())
--   elseif data_type == data_type_enum.PROGRAMMING_CODE then
--     device:emit_event(lockStatusForUser.lockUserChangeDataType.programmingCode())
--   elseif data_type == data_type_enum.USER_INDEX then
--     device:emit_event(lockStatusForUser.lockUserChangeDataType.userIndex())
--   elseif data_type == data_type_enum.WEEK_DAY_SCHEDULE then
--     device:emit_event(lockStatusForUser.lockUserChangeDataType.weekDaySchedule())
--   elseif data_type == data_type_enum.YEAR_DAY_SCHEDULE then
--     device:emit_event(lockStatusForUser.lockUserChangeDataType.yearDaySchedule())
--   elseif data_type == data_type_enum.HOLIDAY_SCHEDULE then
--     device:emit_event(lockStatusForUser.lockUserChangeDataType.holidaySchedule())
--   elseif data_type == data_type_enum.PIN then
--     device:emit_event(lockStatusForUser.lockUserChangeDataType.pin())
--   elseif data_type == data_type_enum.RFID then
--     device:emit_event(lockStatusForUser.lockUserChangeDataType.rfid())
--   elseif data_type == data_type_enum.FINGERPRINT then
--     device:emit_event(lockStatusForUser.lockUserChangeDataType.fingerprint())
--   elseif data_type == data_type_enum.FINGER_VEIN then
--     device:emit_event(lockStatusForUser.lockUserChangeDataType.fingerVein())
--   elseif data_type == data_type_enum.FACE then
--     device:emit_event(lockStatusForUser.lockUserChangeDataType.face())
--   else
--     device:emit_event(lockStatusForUser.lockUserChangeDataType.unspecified())
--   end
--   if operation_type == operation_type_enum.ADD then
--     device:emit_event(lockStatusForUser.lockUserChangeOpType.add())
--   elseif operation_type == operation_type_enum.CLEAR then
--     device:emit_event(lockStatusForUser.lockUserChangeOpType.clear())
--   elseif operation_type == operation_type_enum.MODIFY then
--     device:emit_event(lockStatusForUser.lockUserChangeOpType.modify())
--   end
--   if operation_source == operation_source_enum.UNSPECIFIED then
--     device:emit_event(lockStatusForUser.lockUserChangeSource.unspecified())
--   elseif operation_source == operation_source_enum.MANUAL then
--     device:emit_event(lockStatusForUser.lockUserChangeSource.manual())
--   elseif operation_source == operation_source_enum.PROPRIETARY_REMOTE then
--     device:emit_event(lockStatusForUser.lockUserChangeSource.proprietaryRemote())
--   elseif operation_source == operation_source_enum.KEYPAD then
--     device:emit_event(lockStatusForUser.lockUserChangeSource.keypad())
--   elseif operation_source == operation_source_enum.AUTO then
--     device:emit_event(lockStatusForUser.lockUserChangeSource.auto())
--   elseif operation_source == operation_source_enum.BUTTON then
--     device:emit_event(lockStatusForUser.lockUserChangeSource.button())
--   elseif operation_source == operation_source_enum.SCHEDULE then
--     device:emit_event(lockStatusForUser.lockUserChangeSource.schedule())
--   elseif operation_source == operation_source_enum.REMOTE then
--     device:emit_event(lockStatusForUser.lockUserChangeSource.remote())
--   elseif operation_source == operation_source_enum.RFID then
--     device:emit_event(lockStatusForUser.lockUserChangeSource.rfid())
--   elseif operation_source == operation_source_enum.BIOMETRIC then
--     device:emit_event(lockStatusForUser.lockUserChangeSource.biometric())
--   else
--     device:emit_event(lockStatusForUser.lockUserChangeSource.unspecified())
--   end
-- end






























----------------
-- User Table --
----------------
local function add_user_to_table(device, userIdx, usrType)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! add_user_to_table !!!!!!!!!!!!!"))

  -- Get latest user table
  local user_table = device:get_latest_state(
    "main",
    capabilities.lockUsers.ID,
    capabilities.lockUsers.users.NAME
  ) or {}
  local new_user_table = {}

  -- Recreate user table
  for index, entry in pairs(user_table) do
    table.insert(new_user_table, entry)
  end

  -- Add new entry to table
  table.insert(new_user_table, {userIndex = userIdx, userType = usrType})
  device:emit_event(capabilities.lockUsers.users(new_user_table))
end

local function update_user_in_table(device, userIdx, usrType)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! update_user_in_table !!!!!!!!!!!!!"))

  -- Get latest user table
  local user_table = device:get_latest_state(
    "main",
    capabilities.lockUsers.ID,
    capabilities.lockUsers.users.NAME
  ) or {}
  local new_user_table = {}

  -- Recreate user table
  local i = 0
  for index, entry in pairs(user_table) do
    if entry.userIndex == userIdx then
      i = index
    end
    table.insert(new_user_table, entry)
  end

  -- Update user entry
  if i ~= 0 then
    new_user_table[i].userType = usrType
    device:emit_event(capabilities.lockUsers.users(new_user_table))
  end
end

local function delete_user_from_table(device, userIdx)
  -- If User Index is ALL_INDEX, remove all entry from the table
  if userIdx == ALL_INDEX then
    device:emit_event(capabilities.lockUsers.users({}))
  end

  -- Get latest user table
  local user_table = device:get_latest_state(
    "main",
    capabilities.lockUsers.ID,
    capabilities.lockUsers.users.NAME
  ) or {}
  local new_user_table = {}

  -- find user entry
  for index, entry in pairs(user_table) do
    if entry.userIndex ~= userIdx then
      table.insert(new_user_table, entry)
    end
  end

  device:emit_event(capabilities.lockUsers.users(new_user_table))
end

--------------
-- Add User --
--------------
local function handle_add_user2(device, userIdx, userName, userType, ep)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_add_user !!!!!!!!!!!!!"))

  -- Get parameters
  local cmdName = "addUser"
  -- local userName = command.args.userName
  -- local userType = command.args.lockUserType
  local userTypeMatter = DoorLock.types.UserTypeEnum.UNRESTRICTED_USER
  if userType == "guest" then
    userTypeMatter = DoorLock.types.UserTypeEnum.SCHEDULE_RESTRICTED_USER
  end

  -- Check busy state
  local busy = device:get_field(lock_utils.BUSY_STATE)
  if busy == true then
    local result = {
      commandName = cmdName,
      statusCode = "busy"
    }
    local event = capabilities.lockUsers.commandResult(result, {visibility = {displayed = false}})
    device:emit_event(event)
    return
  end

  -- Save values to field
  device:set_field(lock_utils.BUSY_STATE, true, {persist = true})
  device:set_field(lock_utils.COMMAND_NAME, cmdName, {persist = true})
  device:set_field(lock_utils.USER_INDEX, userIdx, {persist = true})
  device:set_field(lock_utils.USER_TYPE, userType, {persist = true})

  log.info_with({hub_logs=true}, string.format("commandName: %s", cmdName))
  log.info_with({hub_logs=true}, string.format("userIdx: %s", userIdx))
  log.info_with({hub_logs=true}, string.format("userName: %s", userName))
  log.info_with({hub_logs=true}, string.format("userType: %s", userType))
  log.info_with({hub_logs=true}, string.format("userTypeMatter: %s", userTypeMatter))

  -- Send command
  device:send(
    DoorLock.server.commands.SetUser(
      device, ep,
      DoorLock.types.DlDataOperationType.ADD, -- Operation Type: Add(0), Modify(2)
      userIdx,          -- User Index
      userName,         -- User Name
      nil,              -- Unique ID
      nil,              -- User Status
      userTypeMatter,   -- User Type
      nil               -- Credential Rule
    )
  )
end

-----------------
-- Update User --
-----------------
local function handle_update_user(device, userIdx, userName, userType, ep)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_update_user !!!!!!!!!!!!!"))

  -- Get parameters
  local cmdName = "updateUser"
  -- local userIdx = command.args.userIndex
  -- local userName = command.args.userName
  -- local userType = command.args.lockUserType
  local userTypeMatter = DoorLock.types.UserTypeEnum.UNRESTRICTED_USER
  if userType == "guest" then
    userTypeMatter = DoorLock.types.UserTypeEnum.SCHEDULE_RESTRICTED_USER
  end

  -- Check busy state
  local busy = device:get_field(lock_utils.BUSY_STATE)
  if busy == true then
    local result = {
      commandName = cmdName,
      statusCode = "busy"
    }
    local event = capabilities.lockUsers.commandResult(result, {visibility = {displayed = false}})
    device:emit_event(event)
    return
  end

  -- Save values to field
  device:set_field(lock_utils.BUSY_STATE, true, {persist = true})
  device:set_field(lock_utils.COMMAND_NAME, cmdName, {persist = true})
  device:set_field(lock_utils.USER_INDEX, userIdx, {persist = true})
  device:set_field(lock_utils.USER_TYPE, userType, {persist = true})

  log.info_with({hub_logs=true}, string.format("commandName: %s", cmdName))
  log.info_with({hub_logs=true}, string.format("userIndex: %s", userIdx))
  log.info_with({hub_logs=true}, string.format("userName: %s", userName))
  log.info_with({hub_logs=true}, string.format("userType: %s", userType))

  -- Send command
  device:send(
    DoorLock.server.commands.SetUser(
      device, ep,
      DoorLock.types.DlDataOperationType.MODIFY, -- Operation Type: Add(0), Modify(2)
      userIdx,        -- User Index
      userName,       -- User Name
      nil,            -- Unique ID
      nil,            -- User Status
      userTypeMatter, -- User Type
      nil             -- Credential Rule
    )
  )
end

-----------------------
-- Set User Response --
-----------------------
local function set_user_response_handler(driver, device, ib, response)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! set_user_response_handler !!!!!!!!!!!!!"))

  -- Get result
  local cmdName = device:get_field(lock_utils.COMMAND_NAME)
  local userIdx = device:get_field(lock_utils.USER_INDEX)
  local userType = device:get_field(lock_utils.USER_TYPE)
  local status = "success"
  if ib.status == DoorLock.types.DlStatus.FAILURE then
    status = "failure"
  elseif ib.status == DoorLock.types.DlStatus.OCCUPIED then
    status = "occupied"
  elseif ib.status == DoorLock.types.DlStatus.INVALID_FIELD then
    status = "invalidCommand"
  end

  log.info_with({hub_logs=true}, string.format("commandName: %s", cmdName))
  log.info_with({hub_logs=true}, string.format("userIdx: %s", userIdx))
  log.info_with({hub_logs=true}, string.format("userType: %s", userType))
  log.info_with({hub_logs=true}, string.format("status: %s", status))

  -- Update User in table
  -- if status == "success" then
    if cmdName == "addUser" then
      add_user_to_table(device, userIdx, userType)
    elseif cmdName == "updateUser" then
      update_user_in_table(device, userIdx, userType)
    end
  -- end

  -- Update commandResult
  local result = {
    commandName = cmdName,
    userIndex = userIdx,
    statusCode = status
  }
  local event = capabilities.lockUsers.commandResult(result, {visibility = {displayed = false}})
  device:emit_event(event)
  device:set_field(lock_utils.BUSY_STATE, false, {persist = true})
end

-----------------
-- Delete User --
-----------------
local function handle_delete_user(device, userIdx, ep)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_delete_user !!!!!!!!!!!!!"))

  -- Get parameters
  local cmdName = "deleteUser"
  -- local userIdx = command.args.userIndex

  -- Check busy state
  local busy = device:get_field(lock_utils.BUSY_STATE)
  if busy == true then
    local result = {
      commandName = cmdName,
      statusCode = "busy"
    }
    local event = capabilities.lockUsers.commandResult(result, {state_change = true, visibility = {displayed = false}})
    device:emit_event(event)
    return
  end

  -- Save values to field
  device:set_field(lock_utils.BUSY_STATE, true, {persist = true})
  device:set_field(lock_utils.COMMAND_NAME, cmdName, {persist = true})
  device:set_field(lock_utils.USER_INDEX, userIdx, {persist = true})

  log.info_with({hub_logs=true}, string.format("commandName: %s", cmdName))
  log.info_with({hub_logs=true}, string.format("userIndex: %s", userIdx))

  -- Send command
  device:send(DoorLock.server.commands.ClearUser(device, ep, userIdx))
end

----------------------
-- Delete All Users --
----------------------
local function handle_delete_all_users(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_delete_all_users !!!!!!!!!!!!!"))

  -- Get parameters
  local cmdName = "deleteAllUsers"

  -- Check busy state
  local busy = device:get_field(lock_utils.BUSY_STATE)
  if busy == true then
    local result = {
      commandName = cmdName,
      statusCode = "busy"
    }
    local event = capabilities.lockUsers.commandResult(result, {visibility = {displayed = false}})
    device:emit_event(event)
    return
  end

  -- Save values to field
  device:set_field(lock_utils.BUSY_STATE, true, {persist = true})
  device:set_field(lock_utils.COMMAND_NAME, cmdName, {persist = true})
  device:set_field(lock_utils.USER_INDEX, ALL_INDEX, {persist = true})

  log.info_with({hub_logs=true}, string.format("commandName: %s", cmdName))

  -- Send command
  device:send(DoorLock.server.commands.ClearUser(device, ep, ALL_INDEX))
end

-------------------------
-- Clear User Response --
-------------------------
local function clear_user_response_handler(driver, device, ib, response)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! clear_user_response_handler !!!!!!!!!!!!!"))

  -- Get result
  local cmdName = device:get_field(lock_utils.COMMAND_NAME)
  local userIdx = device:get_field(lock_utils.USER_INDEX)
  local status = "success"
  if ib.status == DoorLock.types.DlStatus.FAILURE then
    status = "failure"
  elseif ib.status == DoorLock.types.DlStatus.INVALID_FIELD then
    status = "invalidCommand"
  end

  log.info_with({hub_logs=true}, string.format("commandName: %s", cmdName))
  log.info_with({hub_logs=true}, string.format("userIdx: %s", userIdx))
  log.info_with({hub_logs=true}, string.format("status: %s", status))


  -- Delete User in table
  -- if status == "success" then
    delete_user_from_table(device, userIdx)
  -- end

  -- Update commandResult
  local result = {
    commandName = cmdName,
    userIndex = userIdx,
    statusCode = status
  }
  local event = capabilities.lockUsers.commandResult(result, {visibility = {displayed = false}})
  device:emit_event(event)
  device:set_field(lock_utils.BUSY_STATE, false, {persist = true})
end

----------------------
-- Credential Table --
----------------------
local function add_credential_to_table(device, userIdx, credIdx, credType)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! add_credential_to_table !!!!!!!!!!!!!"))

  -- Get latest credential table
  local cred_table = device:get_latest_state(
    "main",
    capabilities.lockCredentials.ID,
    capabilities.lockCredentials.credentials.NAME
  ) or {}
  local new_cred_table = {}

  -- Recreat credential table
  for index, entry in pairs(cred_table) do
    table.insert(new_cred_table, entry)
  end

  -- Add new entry to table
  table.insert(new_cred_table, {userIndex = userIdx, credentialIndex = credIdx, credentialType = credType})
  device:emit_event(capabilities.lockCredentials.credentials(new_cred_table))
end

local function delete_credential_from_table(device, credIdx)
  -- If Credential Index is ALL_INDEX, remove all entry from the table
  if credIdx == ALL_INDEX then
    device:emit_event(capabilities.lockCredentials.credentials({}))
  end

  -- Get latest credential table
  local cred_table = device:get_latest_state(
    "main",
    capabilities.lockCredentials.ID,
    capabilities.lockCredentials.credentials.NAME
  ) or {}
  local new_cred_table = {}

  -- Recreate credential table
  local i = 0
  for index, entry in pairs(cred_table) do
    if entry.credentialIndex ~= credIdx then
      table.insert(new_cred_table, entry)
    end
  end

  device:emit_event(capabilities.lockCredentials.credentials(new_cred_table))
end

--------------------
-- Add Credential --
--------------------
local function handle_add_credential(device, userIdx, userType, credData, ep)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_add_credential !!!!!!!!!!!!!"))

  -- Get parameters
  local cmdName = "addCredential"
  -- local userIdx = command.args.userIndex
  if userIdx == 0 then
    userIdx = nil
  end
  -- local userType = command.args.userType
  if userType == "guest" then
    userType = DoorLock.types.UserTypeEnum.SCHEDULE_RESTRICTED_USER
  else
    userType = DoorLock.types.UserTypeEnum.UNRESTRICTED_USER
  end
  local credential = {
    credential_type = DoorLock.types.CredentialTypeEnum.PIN,
    credential_index = INITIAL_COTA_INDEX
  }
  -- local credData = command.args.credentialData

  -- Check busy state
  local busy = device:get_field(lock_utils.BUSY_STATE)
  if busy == true then
    local result = {
      commandName = cmdName,
      statusCode = "busy"
    }
    local event = capabilities.lockCredentials.commandResult(result, {visibility = {displayed = false}})
    device:emit_event(event)
    return
  end

  -- Save values to field
  device:set_field(lock_utils.BUSY_STATE, true, {persist = true})
  device:set_field(lock_utils.COMMAND_NAME, cmdName, {persist = true})
  device:set_field(lock_utils.USER_INDEX, userIdx, {persist = true})
  device:set_field(lock_utils.USER_TYPE, userType, {persist = true})
  device:set_field(lock_utils.CRED_INDEX, INITIAL_COTA_INDEX, {persist = true})
  device:set_field(lock_utils.CRED_DATA, credData, {persist = true})

  log.info_with({hub_logs=true}, string.format("commandName: %s", cmdName))
  log.info_with({hub_logs=true}, string.format("userIndex: %s", userIdx))
  log.info_with({hub_logs=true}, string.format("userType: %s", userType))
  log.info_with({hub_logs=true}, string.format("credIndex: %s", INITIAL_COTA_INDEX))
  log.info_with({hub_logs=true}, string.format("credData: %s", credData))

  -- Send command
  device:send(
    DoorLock.server.commands.SetCredential(
      device, ep,
      DoorLock.types.DlDataOperationType.ADD, -- Data Operation Type: Add(0), Modify(2)
      credential,  -- Credential
      credData,    -- Credential Data
      userIdx,     -- User Index
      nil,         -- User Status
      userType     -- User Type
    )
  )
end

-----------------------
-- Update Credential --
-----------------------
local function handle_update_credential(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_update_credential !!!!!!!!!!!!!"))

  -- Get parameters
  local cmdName = "updateCredential"
  local userIdx = command.args.userIndex
  local credIdx = command.args.credentialIndex
  local credential = {
    credential_type = DoorLock.types.CredentialTypeEnum.PIN,
    credential_index = credIdx
  }
  local credData = command.args.credentialData

  -- Check busy state
  local busy = device:get_field(lock_utils.BUSY_STATE)
  if busy == true then
    local result = {
      commandName = cmdName,
      statusCode = "busy"
    }
    local event = capabilities.lockCredentials.commandResult(result, {visibility = {displayed = false}})
    device:emit_event(event)
    return
  end

  -- Save values to field
  device:set_field(lock_utils.BUSY_STATE, true, {persist = true})
  device:set_field(lock_utils.COMMAND_NAME, cmdName, {persist = true})
  device:set_field(lock_utils.USER_INDEX, userIdx, {persist = true})
  device:set_field(lock_utils.CRED_INDEX, credIdx, {persist = true})

  log.info_with({hub_logs=true}, string.format("commandName: %s", cmdName))
  log.info_with({hub_logs=true}, string.format("userIndex: %s", userIdx))
  log.info_with({hub_logs=true}, string.format("credentialIndex: %s", credIdx))
  log.info_with({hub_logs=true}, string.format("credData: %s", credData))

  -- Send command
  local ep = device:component_to_endpoint(command.component)
  device:send(
    DoorLock.server.commands.SetCredential(
      device, ep,
      DoorLock.types.DlDataOperationType.MODIFY, -- Data Operation Type: Add(0), Modify(2)
      credential,  -- Credential
      credData,    -- Credential Data
      userIdx,     -- User Index
      nil,         -- User Status
      nil          -- User Type
    )
  )
end

-----------------------------
-- Set Credential Response --
-----------------------------
local function set_credential_response_handler(driver, device, ib, response)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! set_credential_response_handler !!!!!!!!!!!!!"))

  if ib.status ~= im.InteractionResponse.Status.SUCCESS then
    device.log.error("Failed to set credential for device")
    return
  end

  local cmdName = device:get_field(lock_utils.COMMAND_NAME)
  local credIdx = device:get_field(lock_utils.CRED_INDEX)
  local status = "success"
  local elements = ib.info_block.data.elements
  if elements.status.value == 0 then -- Success
    -- Update Credential table
    local userIdx = elements.user_index.value
    if cmdName == "addCredential" then
      add_credential_to_table(device, userIdx, credIdx, "pin")
    end

    -- Update commandResult
    local result = {
      commandName = cmdName,
      userIndex = userIdx,
      credentialIndex = credIdx,
      statusCode = status
    }
    local event = capabilities.lockCredentials.commandResult(result, {visibility = {displayed = false}})
    device:emit_event(event)
    device:set_field(lock_utils.BUSY_STATE, false, {persist = true})
    return
  end

  log.info_with({hub_logs=true}, string.format("cmdName: %s", cmdName))
  log.info_with({hub_logs=true}, string.format("credIdx: %s", credIdx))

  -- @field public byte_length number 1
  -- @field public SUCCESS number 0
  -- @field public FAILURE number 1
  -- @field public DUPLICATE number 2
  -- @field public OCCUPIED number 3
  -- @field public INVALID_FIELD number 133
  -- @field public RESOURCE_EXHAUSTED number 137
  -- @field public NOT_FOUND number 139

  -- Update commandResult
  status = "occupied"
  if elements.status.value == DoorLock.types.DlStatus.FAILURE then
    status = "failure"
  elseif elements.status.value == DoorLock.types.DlStatus.DUPLICATE then
    status = "duplicate"
  elseif elements.status.value == DoorLock.types.DlStatus.INVALID_FIELD then
    status = "invalidCommand"
  elseif elements.status.value == DoorLock.types.DlStatus.RESOURCE_EXHAUSTED then
    status = "resourceExhausted"
  elseif elements.status.value == DoorLock.types.DlStatus.NOT_FOUND then
    status = "failure"
  end
  log.info_with({hub_logs=true}, string.format("Result: %s", status))

  if status ~= "occupied" then
    local result = {
      commandName = cmdName,
      statusCode = status
    }
    local event = capabilities.lockCredentials.commandResult(result, {visibility = {displayed = false}})
    device:emit_event(event)
    device:set_field(lock_utils.BUSY_STATE, false, {persist = true})
    return
  end

  if elements.next_credential_index.value ~= nil then
    -- Get parameters
    local credIdx = elements.next_credential_index.value
    local credential = {
      credential_type = DoorLock.types.DlCredentialType.PIN,
      credential_index = credIdx,
    }
    local credData = device:get_field(lock_utils.CRED_DATA)
    local userIdx = device:get_field(lock_utils.USER_INDEX)
    local userType = device:get_field(lock_utils.USER_TYPE)

    log.info_with({hub_logs=true}, string.format("credentialIndex: %s", credIdx))
    log.info_with({hub_logs=true}, string.format("credData: %s", credData))
    log.info_with({hub_logs=true}, string.format("userIndex: %s", userIdx))
    log.info_with({hub_logs=true}, string.format("userType: %s", userType))

    device:set_field(lock_utils.CRED_INDEX, credIdx, {persist = true})

    -- Sned command
    local ep = find_default_endpoint(device, DoorLock.ID)
    device:send(
      DoorLock.server.commands.SetCredential(
        device, ep,
        DoorLock.types.DlDataOperationType.ADD, -- Data Operation Type: Add(0), Modify(2)
        credential,  -- Credential
        credData,    -- Credential Data
        userIdx,     -- User Index
        nil,         -- User Status
        userType     -- User Type
      )
    )
  end
end

-----------------------
-- Delete Credential --
-----------------------
local function handle_delete_credential(device, credIdx, ep)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_delete_credential !!!!!!!!!!!!!"))

  -- Get parameters
  local cmdName = "deleteCredential"
  -- local credIdx = command.args.credentialIndex
  local credential = {
    credential_type = DoorLock.types.DlCredentialType.PIN,
    credential_index = credIdx,
  }

  -- Check busy state
  local busy = device:get_field(lock_utils.BUSY_STATE)
  if busy == true then
    local result = {
      commandName = cmdName,
      statusCode = "busy"
    }
    local event = capabilities.lockCredentials.commandResult(result, {visibility = {displayed = false}})
    device:emit_event(event)
    return
  end

  -- Save values to field
  device:set_field(lock_utils.BUSY_STATE, true, {persist = true})
  device:set_field(lock_utils.COMMAND_NAME, cmdName, {persist = true})
  device:set_field(lock_utils.CRED_INDEX, credIdx, {persist = true})

  log.info_with({hub_logs=true}, string.format("commandName: %s", cmdName))
  log.info_with({hub_logs=true}, string.format("credentialIndex: %s", credIdx))

  -- local ep = device:component_to_endpoint(command.component)
  device:send(DoorLock.server.commands.ClearCredential(device, ep, credential))
end

----------------------------
-- Delete All Credentials --
----------------------------
local function handle_delete_all_credentials(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_delete_all_credentials !!!!!!!!!!!!!"))

  -- Get parameters
  local cmdName = "deleteAllCredentials"
  local credential = {
    credential_type = DoorLock.types.DlCredentialType.PIN,
    credential_index = ALL_INDEX,
  }

  -- Check busy state
  local busy = device:get_field(lock_utils.BUSY_STATE)
  if busy == true then
    local result = {
      commandName = cmdName,
      statusCode = "busy"
    }
    local event = capabilities.lockCredentials.commandResult(result, {visibility = {displayed = false}})
    device:emit_event(event)
    return
  end

  -- Save values to field
  device:set_field(lock_utils.BUSY_STATE, true, {persist = true})
  device:set_field(lock_utils.COMMAND_NAME, cmdName, {persist = true})
  device:set_field(lock_utils.CRED_INDEX, ALL_INDEX, {persist = true})

  log.info_with({hub_logs=true}, string.format("commandName: %s", cmdName))
  log.info_with({hub_logs=true}, string.format("credentialIndex: %s", ALL_INDEX))

  -- Send command
  local ep = device:component_to_endpoint(command.component)
  device:send(DoorLock.server.commands.ClearUser(device, ep, credential))
end

-------------------------------
-- Clear Credential Response --
-------------------------------
local function clear_credential_response_handler(driver, device, ib, response)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! clear_credential_response_handler !!!!!!!!!!!!!"))

  -- Get result
  local cmdName = device:get_field(lock_utils.COMMAND_NAME)
  local credIdx = device:get_field(lock_utils.CRED_INDEX)
  local status = "success"
  if ib.status == DoorLock.types.DlStatus.FAILURE then
    status = "failure"
  elseif ib.status == DoorLock.types.DlStatus.INVALID_FIELD then
    status = "invalidCommand"
  end

  -- Delete User in table
  -- if status == "success" then
    delete_credential_from_table(device, credIdx)
  -- end

  -- Update commandResult
  local result = {
    commandName = cmdName,
    credentialIndex = credIdx,
    statusCode = status
  }
  local event = capabilities.lockCredentials.commandResult(result, {visibility = {displayed = false}})
  device:emit_event(event)
  device:set_field(lock_utils.BUSY_STATE, false, {persist = true})
end

-----------------------------
-- Week Day Schedule Table --
-----------------------------
local WEEK_DAY_MAP = {
  ["Sunday"] = 1,
  ["Monday"] = 2,
  ["Tuesday"] = 4,
  ["Wednesday"] = 8,
  ["Thursday"] = 16,
  ["Friday"] = 32,
  ["Saturday"] = 64,
}

local function add_week_schedule_to_table(device, userIdx, scheduleIdx, schedule)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! add_week_schedule_to_table !!!!!!!!!!!!!"))

  -- Get latest week day schedule table
  local week_schedule_table = device:get_latest_state(
    "main",
    capabilities.lockSchedules.ID,
    capabilities.lockSchedules.weekDaySchedules.NAME
  ) or {}
  local new_week_schedule_table = {}

  -- Find shcedule list
  local i = 0
  for index, entry in pairs(week_schedule_table) do
    if entry.userIndex == userIdx then
      i = index
    end
    table.insert(new_week_schedule_table, entry)
  end

  -- Recreate weekDays list
  local weekDayList = {}
  for _, weekday in ipairs(schedule.weekDays) do
    table.insert(weekDayList, weekday)
    log.info_with({hub_logs=true}, string.format("weekDay: %s", weekday))
  end

  if i ~= 0 then -- Add schedule for existing user
    local new_schedule_table = {}
    for index, entry in pairs(new_week_schedule_table[i].schedules) do
      if entry.scheduleIndex == scheduleIdx then
        return
      end
      table.insert(new_schedule_table, entry)
    end

    table.insert(
      new_schedule_table,
      {
        scheduleIndex = scheduleIdx,
        weekdays = weekDayList,
        startHour = schedule.startHour,
        startMinute = schedule.startMinute,
        endHour = schedule.endHour,
        endMinute = schedule.endMinute
      }
    )

    new_week_schedule_table[i].schedules = new_schedule_table
  else -- Add schedule for new user
    log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! add_week_schedule_to_table 2!!!!!!!!!!!!!"))
    table.insert(
      new_week_schedule_table,
      {
        userIndex = userIdx,
        schedules = {{
          scheduleIndex = scheduleIdx,
          weekdays = weekDayList,
          startHour = schedule.startHour,
          startMinute = schedule.startMinute,
          endHour = schedule.endHour,
          endMinute = schedule.endMinute
        }}
      }
    )
  end

  device:emit_event(capabilities.lockSchedules.weekDaySchedules(new_week_schedule_table))
end

local function delete_week_schedule_to_table(device, userIdx, scheduleIdx)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! delete_week_schedule_to_table !!!!!!!!!!!!!"))

  -- Get latest week day schedule table
  local week_schedule_table = device:get_latest_state(
    "main",
    capabilities.lockSchedules.ID,
    capabilities.lockSchedules.weekDaySchedules.NAME
  ) or {}
  local new_week_schedule_table = {}

  -- Find shcedule list
  local i = 0
  for index, entry in pairs(week_schedule_table) do
    if entry.userIndex == userIdx then
      i = index
    end
    table.insert(new_week_schedule_table, entry)
  end

  -- When there is no userIndex in the table
  if i == 0 then
    log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! No userIndex in Week Day Schedule Table !!!!!!!!!!!!!", i))
    return
  end

  -- Recreate schedule table for the user
  local new_schedule_table = {}
  for index, entry in pairs(new_week_schedule_table[i].schedules) do
    if entry.scheduleIndex ~= scheduleIdx then
      table.insert(new_schedule_table, entry)
    end
  end

  -- If user has no schedule, remove user from the table
  if #new_schedule_table == 0 then
    log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! No schedule for User !!!!!!!!!!!!!", i))
    table.remove(new_week_schedule_table, i)
  else
    new_week_schedule_table[i].schedules = new_schedule_table
  end

  device:emit_event(capabilities.lockSchedules.weekDaySchedules(new_week_schedule_table))
end

---------------------------
-- Set Week Day Schedule --
---------------------------
local function handle_set_week_day_schedule(device, userIdx, scheduleIdx, schedule, ep)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_set_week_day_schedule !!!!!!!!!!!!!"))

  -- Get parameters
  local cmdName = "setWeekDaySchedule"
  -- local scheduleIdx = command.args.scheduleIndex
  -- local userIdx = command.args.userIndex
  -- local schedule = command.args.schedule
  local scheduleBit = 0
  for _, weekDay in ipairs(schedule.weekDays) do
    scheduleBit = scheduleBit + WEEK_DAY_MAP[weekDay]
    log.info_with({hub_logs=true}, string.format("%s, %s", WEEK_DAY_MAP[weekDay], weekDay))
  end
  local startHour = schedule.startHour
  local startMinute = schedule.startMinute
  local endHour = schedule.endHour
  local endMinute = schedule.endMinute

  -- Check busy state
  local busy = device:get_field(lock_utils.BUSY_STATE)
  if busy == true then
    local result = {
      commandName = cmdName,
      statusCode = "busy"
    }
    local event = capabilities.lockSchedules.commandResult(result, {visibility = {displayed = false}})
    device:emit_event(event)
    return
  end

  -- Save values to field
  device:set_field(lock_utils.BUSY_STATE, true, {persist = true})
  device:set_field(lock_utils.COMMAND_NAME, cmdName, {persist = true})
  device:set_field(lock_utils.USER_INDEX, userIdx, {persist = true})
  device:set_field(lock_utils.SCHEDULE_INDEX, scheduleIdx, {persist = true})
  device:set_field(lock_utils.SCHEDULE, schedule, {persist = true})

  log.info_with({hub_logs=true}, string.format("commandName: %s", cmdName))
  log.info_with({hub_logs=true}, string.format("scheduleIndex: %s", scheduleIdx))
  log.info_with({hub_logs=true}, string.format("userIndex: %s", userIdx))
  log.info_with({hub_logs=true}, string.format("weekDay[1]: %s", schedule.weekDays[1]))
  log.info_with({hub_logs=true}, string.format("weekDay[2]: %s", schedule.weekDays[2]))
  log.info_with({hub_logs=true}, string.format("weekDay[3]: %s", schedule.weekDays[3]))
  log.info_with({hub_logs=true}, string.format("weekDay[4]: %s", schedule.weekDays[4]))
  log.info_with({hub_logs=true}, string.format("weekDay[5]: %s", schedule.weekDays[5]))
  log.info_with({hub_logs=true}, string.format("weekDay[6]: %s", schedule.weekDays[6]))
  log.info_with({hub_logs=true}, string.format("weekDay[7]: %s", schedule.weekDays[7]))
  log.info_with({hub_logs=true}, string.format("scheduleBit: %s", scheduleBit))
  log.info_with({hub_logs=true}, string.format("startHour: %s", startHour))
  log.info_with({hub_logs=true}, string.format("startMinute: %s", startMinute))
  log.info_with({hub_logs=true}, string.format("endHour: %s", endHour))
  log.info_with({hub_logs=true}, string.format("endMinute: %s", endMinute))

  -- Send command
  -- local ep = device:component_to_endpoint(command.component)
  device:send(
    DoorLock.server.commands.SetWeekDaySchedule(
      device, ep,
      scheduleIdx,   -- Week Day Schedule Index
      userIdx,       -- User Index
      scheduleBit,   -- Days Mask
      startHour,     -- Start Hour
      00,            -- Start Minute
      endHour,       -- End Hour
      00             -- End Minute
    )
  )
end

------------------------------------
-- Set Week Day Schedule Response --
------------------------------------
local function set_week_day_schedule_handler(driver, device, ib, response)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! set_week_day_schedule_handler !!!!!!!!!!!!!"))

  -- Get result
  local cmdName = device:get_field(lock_utils.COMMAND_NAME)
  local userIdx = device:get_field(lock_utils.USER_INDEX)
  local scheduleIdx = device:get_field(lock_utils.SCHEDULE_INDEX)
  local schedule = device:get_field(lock_utils.SCHEDULE)
  local status = "success"
  if ib.status == DoorLock.types.DlStatus.FAILURE then
    status = "failure"
  elseif ib.status == DoorLock.types.DlStatus.INVALID_FIELD then
    status = "invalidCommand"
  end

  -- Add Week Day Schedule to table
  -- if status == "success" then
    add_week_schedule_to_table(device, userIdx, scheduleIdx, schedule)
  -- end

  -- Update commandResult
  local result = {
    commandName = cmdName,
    userIndex = userIdx,
    scheduleIndex = scheduleIdx,
    statusCode = status
  }
  local event = capabilities.lockSchedules.commandResult(result, {visibility = {displayed = false}})
  device:emit_event(event)
  device:set_field(lock_utils.BUSY_STATE, false, {persist = true})
end

-----------------------------
-- Clear Week Day Schedule --
-----------------------------
local function handle_clear_week_day_schedule(device, scheduleIdx, userIdx, ep)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_clear_week_day_schedule !!!!!!!!!!!!!"))

  -- Get parameters
  local cmdName = "clearWeekDaySchedule"
  -- local scheduleIdx = command.args.scheduleIndex
  -- local userIdx = command.args.userIndex

  -- Check busy state
  local busy = device:get_field(lock_utils.BUSY_STATE)
  if busy == true then
    local result = {
      commandName = cmdName,
      statusCode = "busy"
    }
    local event = capabilities.lockSchedules.commandResult(result, {visibility = {displayed = false}})
    device:emit_event(event)
    return
  end

  device:set_field(lock_utils.BUSY_STATE, true, {persist = true})
  device:set_field(lock_utils.COMMAND_NAME, cmdName, {persist = true})
  device:set_field(lock_utils.SCHEDULE_INDEX, scheduleIdx, {persist = true})
  device:set_field(lock_utils.USER_INDEX, userIdx, {persist = true})

  log.info_with({hub_logs=true}, string.format("commandName: %s", cmdName))
  log.info_with({hub_logs=true}, string.format("scheduleIndex: %s", scheduleIdx))
  log.info_with({hub_logs=true}, string.format("userIndex: %s", userIdx))

  -- Send command
  -- local ep = device:component_to_endpoint(command.component)
  device:send(DoorLock.server.commands.ClearWeekDaySchedule(device, ep, scheduleIdx, userIdx))
end

------------------------------------
-- Clear Week Day Schedule Response --
------------------------------------
local function clear_week_day_schedule_handler(driver, device, ib, response)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! clear_week_day_schedule_handler !!!!!!!!!!!!!"))

  -- Get result
  local cmdName = device:get_field(lock_utils.COMMAND_NAME)
  local scheduleIdx = device:get_field(lock_utils.SCHEDULE_INDEX)
  local userIdx = device:get_field(lock_utils.USER_INDEX)
  local status = "success"
  if ib.status == DoorLock.types.DlStatus.FAILURE then
    status = "failure"
  elseif ib.status == DoorLock.types.DlStatus.INVALID_FIELD then
    status = "invalidCommand"
  end

  -- Delete Week Day Schedule to table
  -- if status == "success" then
    delete_week_schedule_to_table(device, userIdx, scheduleIdx)
  -- end

  -- Update commandResult
  local result = {
    commandName = cmdName,
    userIndex = userIdx,
    scheduleIndex = scheduleIdx,
    statusCode = status
  }
  local event = capabilities.lockSchedules.commandResult(result, {visibility = {displayed = false}})
  device:emit_event(event)
  device:set_field(lock_utils.BUSY_STATE, false, {persist = true})
end









































-- Capability Handler
-----------------
-- Lock/Unlock --
-----------------
local function handle_lock(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_lock !!!!!!!!!!!!!"))
  local ep = device:component_to_endpoint(command.component)
  device:send(DoorLock.server.commands.LockDoor(device, ep))
end

local function handle_unlock(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_unlock !!!!!!!!!!!!!"))
  local ep = device:component_to_endpoint(command.component)
  device:send(DoorLock.server.commands.UnlockDoor(device, ep))
end

--------------------------
-- Lock/Unlock with Pin --
--------------------------
local function handle_lock_with_pin_set_pin(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_lock_with_pin_set_pin !!!!!!!!!!!!!"))

  local pin = command.args.pin
  log.info_with({hub_logs=true}, string.format("pin: %s", pin))
  device:emit_event(lockWithPin.pin(pin, {state_change = true}))
end

local function handle_lock_with_pin(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_lock_with_pin!!!!!!!!!!!!!"))

  local ep = device:component_to_endpoint(command.component)
  local pin = device:get_latest_state("main", lockWithPinID, lockWithPin.pin.NAME)
  log.info_with({hub_logs=true}, string.format("pin: %s", pin))

  device:send(DoorLock.server.commands.LockDoor(device, ep, pin))
end

local function handle_unlock_with_pin(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_unlock_with_pin !!!!!!!!!!!!!"))
  
  local ep = device:component_to_endpoint(command.component)
  local pin = device:get_latest_state("main", lockWithPinID, lockWithPin.pin.NAME)
  log.info_with({hub_logs=true}, string.format("pin: %s", pin))

  device:send(DoorLock.server.commands.UnlockDoor(device, ep, pin))
end

-------------------
-- Lock Add User --
-------------------
local function handle_add_user_set_user_index(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_add_user_set_user_index !!!!!!!!!!!!!"))

  local userIndex = command.args.userIndex
  log.info_with({hub_logs=true}, string.format("userIndex: %s", userIndex))
  device:emit_event(lockAddUser.userIndex(userIndex, {state_change = true}))
end

local function handle_add_user_set_user_type(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_add_user_set_user_type !!!!!!!!!!!!!"))

  local userType = command.args.userType
  log.info_with({hub_logs=true}, string.format("userType: %s", userType))
  device:emit_event(lockAddUser.userType(userType, {state_change = true}))
end

local function handle_add_user(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_add_user !!!!!!!!!!!!!"))
  
  local ep = device:component_to_endpoint(command.component)
  local userIndex = device:get_latest_state("main", lockAddUserID, lockAddUser.userIndex.NAME)
  userIndex = math.tointeger(userIndex)
  local userType = device:get_latest_state("main", lockAddUserID, lockAddUser.userType.NAME)

  if userType == "unrestrictedUser" then
    userType = "adminMember"
  -- elseif userType == "yearDayScheduleUser" then

  -- elseif userType == "weekDayScheduleUser" then

  -- elseif userType == "programmingUser" then

  -- elseif userType == "nonAccessUser" then

  -- elseif userType == "forcedUser" then

  -- elseif userType == "disposableUser" then

  -- elseif userType == "expiringUser" then

  -- elseif userType == "scheduleRestrictedUser" then

  -- elseif userType == "remoteOnlyUser" then
  else
    userType = "guest"
  end

  log.info_with({hub_logs=true}, string.format("userIndex: %s, userType: %s", userIndex, userType))

  handle_add_user2(device, userIndex, "Test" .. userIndex, userType, ep)

  -- device:send(
  --   DoorLock.server.commands.SetUser(
  --     device, ep,
  --     0,          -- Operation Type: Add(0), Modify(2)
  --     userIndex,  -- User Index
  --     nil,        -- User Name
  --     nil,        -- Unique ID
  --     nil,        -- User Status
  --     userType,   -- User Type
  --     nil         -- Credential Rule
  --   )
  -- )
end

----------------------
-- Lock Modify User --
----------------------
local function handle_modify_user_set_user_index(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_modify_user_set_user_index !!!!!!!!!!!!!"))

  local userIndex = command.args.userIndex
  log.info_with({hub_logs=true}, string.format("userIndex: %s", userIndex))
  device:emit_event(lockModifyUser.userIndex(userIndex, {state_change = true}))
end

local function handle_modify_user_set_user_status(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_modify_user_set_user_status !!!!!!!!!!!!!"))

  local userStatus = command.args.userStatus
  log.info_with({hub_logs=true}, string.format("userStatus: %s", userStatus))
  device:emit_event(lockModifyUser.userStatus(userStatus, {state_change = true}))
end

local function handle_modify_user_set_user_type(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_modify_user_set_user_type !!!!!!!!!!!!!"))

  local userType = command.args.userType
  log.info_with({hub_logs=true}, string.format("userType: %s", userType))
  device:emit_event(lockModifyUser.userType(userType, {state_change = true}))
end

local function handle_modify_user(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_modify_user !!!!!!!!!!!!!"))
  
  local ep = device:component_to_endpoint(command.component)
  local userIndex = device:get_latest_state("main", lockModifyUserID, lockModifyUser.userIndex.NAME)
  userIndex = math.tointeger(userIndex)
  local userStatus = device:get_latest_state("main", lockModifyUserID, lockModifyUser.userStatus.NAME)
  log.info_with({hub_logs=true}, string.format("userStatus: %s", userStatus))
  for statusInteger, statusString in pairs(USER_STATUS_MAP) do
    if userStatus == statusString then
      userStatus = stautsInteger
      break
    end
  end
  local userType = device:get_latest_state("main", lockModifyUserID, lockModifyUser.userType.NAME)
  for typeInteger, typeString in pairs(USER_TYPE_MAP) do
    if userType == typeString then
      userType = typeInteger
      break
    end
  end
  log.info_with({hub_logs=true}, string.format("userIndex: %s, userStatus: %s, userType: %s", userIndex, userStatus, userType))

  handle_update_user(device, userIndex, "Test" .. userIndex, userType, ep)

  -- device:send(
  --   DoorLock.server.commands.SetUser(
  --     device, ep,
  --     2,          -- Operation Type: Add(0), Modify(2)
  --     userIndex,  -- User Index
  --     nil,        -- User Name
  --     nil,        -- Unique ID
  --     userStatus, -- User Status
  --     nil,        -- User Type
  --     nil         -- Credential Rule
  --   )
  -- )
end

---------------------
-- Lock Clear User --
---------------------
local function handle_clear_user_set_user_index(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_clear_user_set_user_index !!!!!!!!!!!!!"))

  local userIndex = command.args.userIndex
  log.info_with({hub_logs=true}, string.format("userIndex: %s", userIndex))
  device:emit_event(lockClearUser.userIndex(userIndex, {state_change = true}))
end

local function handle_clear_user(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_clear_user !!!!!!!!!!!!!"))
  
  local ep = device:component_to_endpoint(command.component)
  local userIndex = device:get_latest_state("main", lockClearUserID, lockClearUser.userIndex.NAME)
  userIndex = math.tointeger(userIndex)
  log.info_with({hub_logs=true}, string.format("userIndex: %s", userIndex))
  
  handle_delete_user(device, userIndex, ep)
  -- device:send(DoorLock.server.commands.ClearUser(device, ep, userIndex))
end

-------------------
-- Lock Get User --
-------------------
local function handle_get_user_set_user_index(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_get_user_set_user_index !!!!!!!!!!!!!"))

  local userIndex = command.args.userIndex
  log.info_with({hub_logs=true}, string.format("userIndex: %s", userIndex))
  device:emit_event(lockGetUser.userIndex(userIndex, {state_change = true}))
end

local function handle_get_user(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_get_user !!!!!!!!!!!!!"))

  local ep = device:component_to_endpoint(command.component)
  local userIndex = device:get_latest_state("main", lockGetUserID, lockGetUser.userIndex.NAME)
  userIndex = math.tointeger(userIndex)
  log.info_with({hub_logs=true}, string.format("userIndex: %s", userIndex))
  
  device:send(DoorLock.server.commands.GetUser(device, ep, userIndex))
end

-----------------------
-- Get User Response --
-----------------------
local function get_user_response_handler(driver, device, ib, response)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! get_user_response_handler !!!!!!!!!!!!!"))
  if ib.status ~= im.InteractionResponse.Status.SUCCESS then
    device.log.warn("Not taking action on GetUserResponse because failed status")
    return
  end
  local elements = ib.info_block.data.elements
  local user_name = elements.user_name.value
  local user_uniqueid = elements.user_uniqueid.value
  local user_status = elements.user_status.value
  local user_type = elements.user_type.value
  local credential_rule = elements.credential_rule.value
  local creator_fabric_index = elements.creator_fabric_index.value
  local last_modified_fabric_index = elements.last_modified_fabric_index.value
  local next_user_index = elements.next_user_index.value

  if user_name ~= nil and user_name ~= "" then
    log.info_with({hub_logs=true}, string.format("user_name: %s", user_name))
    device:emit_event(lockGetUser.userName(user_name, {state_change = true}))
  else
    log.info_with({hub_logs=true}, string.format("user_name: null"))
    device:emit_event(lockGetUser.userName("null", {state_change = true}))
  end

  if user_uniqueid ~= nil then
    log.info_with({hub_logs=true}, string.format("user_uniqueid: %s", user_uniqueid))
    device:emit_event(lockGetUser.userUniqueID(tostring(user_uniqueid), {state_change = true}))
  else
    log.info_with({hub_logs=true}, string.format("user_uniqueid: null"))
    device:emit_event(lockGetUser.userUniqueID("null", {state_change = true}))
  end

  if user_status ~= nil then
    log.info_with({hub_logs=true}, string.format("user_status: %s", user_status))
    local status = USER_STATUS_MAP[user_status]
    device:emit_event(lockGetUser.userStatus(status, {state_change = true}))
  else
    log.info_with({hub_logs=true}, string.format("user_status: null"))
    device:emit_event(lockGetUser.userStatus(lockGetUser.userStatus.nullValue.NAME, {state_change = true}))
  end

  if user_type ~= nil then
    log.info_with({hub_logs=true}, string.format("user_type: %s", user_type))
    local type = USER_TYPE_MAP[user_type]
    device:emit_event(lockGetUser.userType(type, {state_change = true}))
  else
    log.info_with({hub_logs=true}, string.format("user_type: null"))
    device:emit_event(lockGetUser.userType(lockGetUser.userType.nullValue.NAME, {state_change = true}))
  end

  if credential_rule ~= nil then
    log.info_with({hub_logs=true}, string.format("credential_rule: %s", credential_rule))
    local cred_rule = lockGetUser.credRule.single.NAME
    if credential_rule == DoorLock.types.CredentialRuleEnum.SINGLE then
      cred_rule = lockGetUser.credRule.single.NAME
    elseif credential_rule == DoorLock.types.CredentialRuleEnum.DUAL then
      cred_rule = lockGetUser.credRule.dule.NAME
    elseif credential_rule == DoorLock.types.CredentialRuleEnum.TRI then
      cred_rule = lockGetUser.credRule.tri.NAME
    end
    device:emit_event(lockGetUser.credRule(cred_rule, {state_change = true}))
  else
    log.info_with({hub_logs=true}, string.format("credential_rule: null"))
    device:emit_event(lockGetUser.credRule(lockGetUser.credRule.nullValue.NAME, {state_change = true}))
  end

  if creator_fabric_index ~= nil then
    log.info_with({hub_logs=true}, string.format("creator_fabric_index: %s", creator_fabric_index))
    device:emit_event(lockGetUser.creatorFabricIndex(tostring(creator_fabric_index), {state_change = true}))
  else
    log.info_with({hub_logs=true}, string.format("creator_fabric_index: null"))
    device:emit_event(lockGetUser.creatorFabricIndex("null", {state_change = true}))
  end

  if last_modified_fabric_index ~= nil then
    log.info_with({hub_logs=true}, string.format("last_modified_fabric_index: %s", last_modified_fabric_index))
    device:emit_event(lockGetUser.lastFabricIndex(tostring(last_modified_fabric_index), {state_change = true}))
  else
    log.info_with({hub_logs=true}, string.format("last_modified_fabric_index: null"))
    device:emit_event(lockGetUser.lastFabricIndex("null", {state_change = true}))
  end

  if next_user_index ~= nil then
    log.info_with({hub_logs=true}, string.format("next_user_index: %s", next_user_index))
    device:emit_event(lockGetUser.nextUserIndex(tostring(next_user_index), {state_change = true}))
  else
    log.info_with({hub_logs=true}, string.format("next_user_index: null"))
    device:emit_event(lockGetUser.nextUserIndex("null", {state_change = true}))
  end
end

------------------
-- Lock Add Pin --
------------------
local function handle_add_pin_set_cred_index(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_add_pin_set_cred_index !!!!!!!!!!!!!"))

  local credIndex = command.args.credIndex
  log.info_with({hub_logs=true}, string.format("credIndex: %s", credIndex))
  device:emit_event(lockAddPin.credIndex(credIndex, {state_change = true}))
end

local function handle_add_pin_set_pin(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_add_pin_set_pin !!!!!!!!!!!!!"))

  local pin = command.args.pin
  log.info_with({hub_logs=true}, string.format("pin: %s", pin))
  device:emit_event(lockAddPin.pin(pin, {state_change = true}))
end

local function handle_add_pin_set_user_index(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_add_pin_set_user_index !!!!!!!!!!!!!"))

  local userIndex = command.args.userIndex
  log.info_with({hub_logs=true}, string.format("userIndex: %s", userIndex))
  device:emit_event(lockAddPin.userIndex(userIndex, {state_change = true}))
end

local function handle_add_pin_set_user_type(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_add_pin_set_user_type !!!!!!!!!!!!!"))

  local userType = command.args.userType
  log.info_with({hub_logs=true}, string.format("userType: %s", userType))
  device:emit_event(lockAddPin.userType(userType, {state_change = true}))
end

local function handle_add_pin(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_add_pin !!!!!!!!!!!!!"))
  
  local ep = device:component_to_endpoint(command.component)
  local credIndex = device:get_latest_state("main", lockAddPinID, lockAddPin.credIndex.NAME)
  credIndex = math.tointeger(credIndex)
  local pin = device:get_latest_state("main", lockAddPinID, lockAddPin.pin.NAME)
  local userIndex = device:get_latest_state("main", lockAddPinID, lockAddPin.userIndex.NAME)
  userIndex = math.tointeger(userIndex)
  local userType = device:get_latest_state("main", lockAddPinID, lockAddPin.userType.NAME)
  for typeInteger, typeString in pairs(USER_TYPE_MAP) do
    if userType == typeString then
      userType = typeInteger
      break
    end
  end
  log.info_with({hub_logs=true}, string.format(
    "credIndex: %s, pin: %s, userIndex: %s, userType: %s",
    credIndex, pin, userIndex, userType
  ))

  handle_add_credential(device, userIndex, userType, pin, ep)

  -- local credential = {credential_type = DoorLock.types.CredentialTypeEnum.PIN, credential_index = credIndex}
  -- device:send(
  --   DoorLock.server.commands.SetCredential(
  --     device, ep,
  --     0,           -- Data Operation Type: Add(0), Modify(2)
  --     credential,  -- Credential
  --     pin,         -- Credential Data
  --     userIndex,   -- User Index
  --     nil,         -- User Status
  --     nil     -- User Type
  --   )
  -- )
end

---------------------
-- Lock Modify Pin --
---------------------
local function handle_modify_pin_set_user_index(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_modify_pin_set_user_index !!!!!!!!!!!!!"))

  local userIndex = command.args.userIndex
  log.info_with({hub_logs=true}, string.format("userIndex: %s", userIndex))
  device:emit_event(lockModifyPin.userIndex(userIndex, {state_change = true}))
end

local function handle_modify_pin_set_cred_index(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_modify_pin_set_cred_index !!!!!!!!!!!!!"))

  local credIndex = command.args.credIndex
  log.info_with({hub_logs=true}, string.format("credIndex: %s", credIndex))
  device:emit_event(lockModifyPin.credIndex(credIndex, {state_change = true}))
end

local function handle_modify_pin_set_pin(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_modify_pin_set_pin !!!!!!!!!!!!!"))

  local pin = command.args.pin
  log.info_with({hub_logs=true}, string.format("pin: %s", pin))
  device:emit_event(lockModifyPin.pin(pin, {state_change = true}))
end

local function handle_modify_pin(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_modify_pin !!!!!!!!!!!!!"))

  local ep = device:component_to_endpoint(command.component)
  local userIndex = device:get_latest_state("main", lockModifyPinID, lockModifyPin.userIndex.NAME)
  userIndex = math.tointeger(userIndex)
  local credIndex = device:get_latest_state("main", lockModifyPinID, lockModifyPin.credIndex.NAME)
  credIndex = math.tointeger(credIndex)
  local pin = device:get_latest_state("main", lockModifyPinID, lockModifyPin.pin.NAME)
  log.info_with({hub_logs=true}, string.format(
    "userIndex: %s, credIndex: %s, pin: %s",
    userIndex, credIndex, pin
  ))

  local credential = {credential_type = DoorLock.types.CredentialTypeEnum.PIN, credential_index = credIndex}
  device:send(
    DoorLock.server.commands.SetCredential(
      device, ep,
      2,           -- Data Operation Type: Add(0), Modify(2)
      credential,  -- Credential
      pin,         -- Credential Data
      userIndex,   -- User Index
      nil,         -- User Status
      nil     -- User Type
    )
  )
end

-----------------------------
-- Set Credential Response --
-----------------------------
-- local function set_credential_response_handler(driver, device, ib, response)
--   log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! set_credential_response_handler !!!!!!!!!!!!!"))

--   local elements = ib.info_block.data.elements
--   -- if ib.status ~= im.InteractionResponse.Status.SUCCESS then
--   --   device.log.error("Failed to set pin for device")
--   --   return
--   -- end

--   local ep = find_default_endpoint(device, DoorLock.ID)
--   if elements.status.value == 0 then -- Success
--     log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! set_credential_response_handler: succcess !!!!!!!!!!!!!"))
--     return
--   end

--   -- @field public byte_length number 1
--   -- @field public SUCCESS number 0
--   -- @field public FAILURE number 1
--   -- @field public DUPLICATE number 2
--   -- @field public OCCUPIED number 3
--   -- @field public INVALID_FIELD number 133
--   -- @field public RESOURCE_EXHAUSTED number 137
--   -- @field public NOT_FOUND number 139
 
--   log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! set_credential_response_handler: failure !!!!!!!!!!!!!"))
--   local result = "Failure"
--   if elements.status.value == DoorLock.types.DlStatus.FAILURE then
--     result = "Failure"
--   elseif elements.status.value == DoorLock.types.DlStatus.DUPLICATE then
--     result = "Duplicate"
--   elseif elements.status.value == DoorLock.types.DlStatus.OCCUPIED then
--     result = "Occupied"
--   elseif elements.status.value == DoorLock.types.DlStatus.INVALID_FIELD then
--     result = "Invalid Field"
--   elseif elements.status.value == DoorLock.types.DlStatus.RESOURCE_EXHAUSTED then
--     result = "Resource Exhausted"
--   elseif elements.status.value == DoorLock.types.DlStatus.NOT_FOUND then
--     result = "Not Found"
--   end
--   log.info_with({hub_logs=true}, string.format("ib.status: %s", ib.status))
--   log.info_with({hub_logs=true}, string.format("Result: %s", result))
--   log.info_with({hub_logs=true}, string.format("Next Credential Index %s", elements.next_credential_index.value))
-- end

--------------------
-- Lock Clear Pin --
--------------------
local function handle_clear_pin_set_cred_index(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_clear_pin_set_cred_index !!!!!!!!!!!!!"))

  local credIndex = command.args.credIndex
  log.info_with({hub_logs=true}, string.format("credIndex: %s", credIndex))
  device:emit_event(lockClearPin.credIndex(credIndex, {state_change = true}))
end

local function handle_clear_pin(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_clear_pin !!!!!!!!!!!!!"))
  
  local ep = device:component_to_endpoint(command.component)
  local credIndex = device:get_latest_state("main", lockClearPinID, lockClearPin.credIndex.NAME)
  credIndex = math.tointeger(credIndex)
  log.info_with({hub_logs=true}, string.format("credIndex: %s", credIndex))
  local credential = {
    credential_type = DoorLock.types.CredentialTypeEnum.PIN,
    credential_index = credIndex
  }

  handle_delete_credential(device, credIndex, ep)
  -- device:send(DoorLock.server.commands.ClearCredential(device, ep, credential))
end

------------------
-- Lock Get Pin --
------------------
local function handle_get_pin_set_cred_index(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_get_pin_set_cred_index !!!!!!!!!!!!!"))

  local credIndex = command.args.credIndex
  log.info_with({hub_logs=true}, string.format("credIndex: %s", credIndex))
  device:emit_event(lockGetPin.credIndex(credIndex, {state_change = true}))
end

local function handle_get_pin(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_get_pin !!!!!!!!!!!!!"))
  
  local ep = device:component_to_endpoint(command.component)
  local credIndex = device:get_latest_state("main", lockGetPinID, lockGetPin.credIndex.NAME)
  credIndex = math.tointeger(credIndex)
  log.info_with({hub_logs=true}, string.format("credIndex: %s", credIndex))
  local credential = {
    credential_type = DoorLock.types.CredentialTypeEnum.PIN,
    credential_index = credIndex
  }

  device:send(DoorLock.server.commands.GetCredentialStatus(device, ep, credential))
end

------------------------------------
-- Get Credential Status Response --
------------------------------------
local function get_credential_status_response_handler(driver, device, ib, response)
  if ib.status ~= im.InteractionResponse.Status.SUCCESS then
    device.log.warn("Not taking action on GetCredentialStatusResponse because failed status")
    return
  end
  local elements = ib.info_block.data.elements
  local credExists = elements.credential_exists.value
  local userIndex = elements.user_index.value
  local creatorFabricIndex = elements.creator_fabric_index.value
  local lastModifiedFabricIndex = elements.last_modified_fabric_index.value
  local nextCredIndex = elements.next_credential_index.value

  if credExists then
    log.info_with({hub_logs=true}, string.format("cred_exists: True"))
    device:emit_event(lockGetPin.exists("True", {state_change = true}))
  else
    log.info_with({hub_logs=true}, string.format("cred_exists: False"))
    device:emit_event(lockGetPin.exists("False", {state_change = true}))
  end

  if userIndex ~= nil then
    log.info_with({hub_logs=true}, string.format("userIndex: %d", userIndex))
    device:emit_event(lockGetPin.userIndex(tostring(userIndex), {state_change = true}))
  else
    log.info_with({hub_logs=true}, string.format("userIndex: null"))
    device:emit_event(lockGetPin.userIndex("Null", {state_change = true}))
  end

  if creatorFabricIndex ~= nil then
    log.info_with({hub_logs=true}, string.format("creatorFabricIndex: %d", creatorFabricIndex))
    device:emit_event(lockGetPin.creatorFabricIndex(tostring(creatorFabricIndex), {state_change = true}))
  else
    log.info_with({hub_logs=true}, string.format("creatorFabricIndex: null"))
    device:emit_event(lockGetPin.creatorFabricIndex("Null", {state_change = true}))
  end

  if lastModifiedFabricIndex ~= nil then
    log.info_with({hub_logs=true}, string.format("lastModifiedFabricIndex: %d", lastModifiedFabricIndex))
    device:emit_event(lockGetPin.lastFabricIndex(tostring(lastModifiedFabricIndex), {state_change = true}))
  else
    log.info_with({hub_logs=true}, string.format("lastModifiedFabricIndex: null"))
    device:emit_event(lockGetPin.lastFabricIndex("Null", {state_change = true}))
  end

  if nextCredIndex ~= nil then
    log.info_with({hub_logs=true}, string.format("nextCredIndex: %d", nextCredIndex))
    device:emit_event(lockGetPin.nextCredIndex(tostring(nextCredIndex), {state_change = true}))
  else
    log.info_with({hub_logs=true}, string.format("nextCredIndex: null"))
    device:emit_event(lockGetPin.nextCredIndex("Null", {state_change = true}))
  end
end

----------------------------
-- Lock Add Week Schedule --
----------------------------
local function handle_add_week_schedule_set_user_index(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_add_week_schedule_set_user_index !!!!!!!!!!!!!"))

  local userIndex = command.args.userIndex
  log.info_with({hub_logs=true}, string.format("userIndex: %s", userIndex))
  device:emit_event(lockAddWeekSchedule.userIndex(userIndex, {state_change = true}))
end

local function handle_add_week_schedule_set_schedule_index(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_add_week_schedule_set_schedule_index !!!!!!!!!!!!!"))

  local scheduleIndex = command.args.scheduleIndex
  log.info_with({hub_logs=true}, string.format("scheduleIndex: %s", scheduleIndex))
  device:emit_event(lockAddWeekSchedule.scheduleIndex(scheduleIndex, {state_change = true}))
end

local function handle_add_week_schedule_set_days_mask(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_add_week_schedule_set_days_mask !!!!!!!!!!!!!"))

  local daysMask = command.args.daysMask
  log.info_with({hub_logs=true}, string.format("daysMask: %s", daysMask))
  device:emit_event(lockAddWeekSchedule.daysMask(daysMask, {state_change = true}))
end

local function handle_add_week_schedule_set_start_hour(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_add_week_schedule_set_start_hour !!!!!!!!!!!!!"))

  local startHour = command.args.startHour
  log.info_with({hub_logs=true}, string.format("startHour: %s", startHour))
  device:emit_event(lockAddWeekSchedule.startHour(startHour, {state_change = true}))
end

local function handle_add_week_schedule_set_end_hour(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_add_week_schedule_set_end_hour !!!!!!!!!!!!!"))

  local endHour = command.args.endHour
  log.info_with({hub_logs=true}, string.format("endHour: %s", endHour))
  device:emit_event(lockAddWeekSchedule.endHour(endHour, {state_change = true}))
end

local function handle_add_week_schedule(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_add_week_schedule !!!!!!!!!!!!!"))
  
  local ep = device:component_to_endpoint(command.component)
  local userIndex = device:get_latest_state("main", lockAddWeekScheduleID, lockAddWeekSchedule.userIndex.NAME)
  userIndex = math.tointeger(userIndex)
  local scheduleIndex = device:get_latest_state("main", lockAddWeekScheduleID, lockAddWeekSchedule.scheduleIndex.NAME)
  scheduleIndex = math.tointeger(scheduleIndex)
  local daysMaskBin = device:get_latest_state("main", lockAddWeekScheduleID, lockAddWeekSchedule.daysMask.NAME)
  local daysMaskDec = tonumber(daysMaskBin, 2)
  local startHour = device:get_latest_state("main", lockAddWeekScheduleID, lockAddWeekSchedule.startHour.NAME)
  startHour = math.tointeger(startHour)
  local endHour = device:get_latest_state("main", lockAddWeekScheduleID, lockAddWeekSchedule.endHour.NAME)
  endHour = math.tointeger(endHour)

  log.info_with({hub_logs=true}, string.format("userIndex: %s, scheduleIndex: %s", userIndex, scheduleIndex))
  log.info_with({hub_logs=true}, string.format("daysMaskBin: %s", daysMaskBin))
  log.info_with({hub_logs=true}, string.format("daysMaskDec: %s", daysMaskDec))
  log.info_with({hub_logs=true}, string.format("startHour: %s, endHour: %s", startHour, endHour))

  local weekdaysList = {}
  if daysMaskDec & 1 ~= 0 then
    table.insert(weekdaysList, "Sunday")
  end
  if daysMaskDec & 2 ~= 0  then
    table.insert(weekdaysList, "Monday")
  end
  if daysMaskDec & 4 ~= 0  then
    table.insert(weekdaysList, "Tuesday")
  end
  if daysMaskDec & 8 ~= 0  then
    table.insert(weekdaysList, "Wednesday")
  end
  if daysMaskDec & 16 ~= 0  then
    table.insert(weekdaysList, "Thursday")
  end
  if daysMaskDec & 32 ~= 0  then
    table.insert(weekdaysList, "Friday")
  end
  if daysMaskDec & 64 ~= 0  then
    table.insert(weekdaysList, "Saturday")
  end

  schedule = {weekDays = weekdaysList, startHour = startHour, startMinute = 00, endHour = endHour, endMinute = 00}
  handle_set_week_day_schedule(device, userIndex, scheduleIndex, schedule, ep)

  -- device:send(
  --   DoorLock.server.commands.SetWeekDaySchedule(
  --     device, ep,
  --     scheduleIndex, -- Week Day Schedule Index
  --     userIndex,     -- User Index
  --     daysMaskDec,   -- Days Mask
  --     startHour,     -- Start Hour
  --     00,            -- Start Minute
  --     endHour,       -- End Hour
  --     00             -- End Minute
  --   )
  -- )
end

------------------------------
-- Lock Clear Week Schedule --
------------------------------
local function handle_clear_week_schedule_set_user_index(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_clear_week_schedule_set_user_index !!!!!!!!!!!!!"))

  local userIndex = command.args.userIndex
  log.info_with({hub_logs=true}, string.format("userIndex: %s", userIndex))
  device:emit_event(lockClearWeekSchedule.userIndex(userIndex, {state_change = true}))
end

local function handle_clear_week_schedule_set_schedule_index(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_clear_week_schedule_set_schedule_index !!!!!!!!!!!!!"))

  local scheduleIndex = command.args.scheduleIndex
  log.info_with({hub_logs=true}, string.format("scheduleIndex: %s", scheduleIndex))
  device:emit_event(lockClearWeekSchedule.scheduleIndex(scheduleIndex, {state_change = true}))
end

local function handle_clear_week_schedule(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_clear_week_schedule !!!!!!!!!!!!!"))
  
  local ep = device:component_to_endpoint(command.component)
  local userIndex = device:get_latest_state("main", lockClearWeekScheduleID, lockClearWeekSchedule.userIndex.NAME)
  userIndex = math.tointeger(userIndex)
  local scheduleIndex = device:get_latest_state("main", lockClearWeekScheduleID, lockClearWeekSchedule.scheduleIndex.NAME)
  scheduleIndex = math.tointeger(scheduleIndex)

  log.info_with({hub_logs=true}, string.format("userIndex: %s, scheduleIndex: %s", userIndex, scheduleIndex))

  handle_clear_week_day_schedule(device, scheduleIndex, userIndex, ep)

  -- device:send(
  --   DoorLock.server.commands.ClearWeekDaySchedule(
  --     device, ep,
  --     scheduleIndex, -- Week Day Schedule Index
  --     userIndex      -- User Index
  --   )
  -- )
end

----------------------------
-- Lock Get Week Schedule --
----------------------------
local function handle_get_week_schedule_set_user_index(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_get_week_schedule_set_user_index !!!!!!!!!!!!!"))

  local userIndex = command.args.userIndex
  log.info_with({hub_logs=true}, string.format("userIndex: %s", userIndex))
  device:emit_event(lockGetWeekSchedule.userIndex(userIndex, {state_change = true}))
end

local function handle_get_week_schedule_set_schedule_index(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_get_week_schedule_set_schedule_index !!!!!!!!!!!!!"))

  local scheduleIndex = command.args.scheduleIndex
  log.info_with({hub_logs=true}, string.format("scheduleIndex: %s", scheduleIndex))
  device:emit_event(lockGetWeekSchedule.scheduleIndex(scheduleIndex, {state_change = true}))
end

local function handle_get_week_schedule(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_get_week_schedule !!!!!!!!!!!!!"))
  
  local ep = device:component_to_endpoint(command.component)
  local userIndex = device:get_latest_state("main", lockGetWeekScheduleID, lockGetWeekSchedule.userIndex.NAME)
  userIndex = math.tointeger(userIndex)
  local scheduleIndex = device:get_latest_state("main", lockGetWeekScheduleID, lockGetWeekSchedule.scheduleIndex.NAME)
  scheduleIndex = math.tointeger(scheduleIndex)

  log.info_with({hub_logs=true}, string.format("userIndex: %s, scheduleIndex: %s", userIndex, scheduleIndex))

  device:send(
    DoorLock.server.commands.GetWeekDaySchedule(
      device, ep,
      scheduleIndex, -- Week Day Schedule Index
      userIndex      -- User Index
    )
  )
end

------------------------------------
-- Get Week Day Schedule Response --
------------------------------------
local function get_week_day_schedule_response_handler(driver, device, ib, response)
  if ib.status ~= im.InteractionResponse.Status.SUCCESS then
    device.log.warn("Not taking action on GetWeekDayScheduleResponse because failed status")
    return
  end

  local elements = ib.info_block.data.elements
  local status = elements.status.value
  local result = "Success"
  if status == DoorLock.types.DlStatus.FAILURE then
    result = "Failure"
  elseif status == DoorLock.types.DlStatus.DUPLICATE then
    result = "Duplicate"
  elseif status == DoorLock.types.DlStatus.OCCUPIED then
    result = "Occupied"
  elseif status == DoorLock.types.DlStatus.INVALID_FIELD then
    result = "Invalid Field"
  elseif status == DoorLock.types.DlStatus.RESOURCE_EXHAUSTED then
    result = "Resource Exhausted"
  elseif status == DoorLock.types.DlStatus.NOT_FOUND then
    result = "Not Found"
  end
  log.info_with({hub_logs=true}, string.format("status: %s", result))
  device:emit_event(lockGetWeekSchedule.status(result, {state_change = true}))
  if status ~= DoorLock.types.DlStatus.SUCCESS then
    log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! get_week_day_schedule_response_handler: failure !!!!!!!!!!!!!"))
    return
  end

  local daysMask = elements.days_mask.value
  local startHour = elements.start_hour.value
  local startMinute = elements.start_minute.value
  local endHour = elements.end_hour.value
  local endMinute = elements.end_minute.value

  if daysMask ~= nil then
    log.info_with({hub_logs=true}, string.format("daysMask: %s", daysMask))
    device:emit_event(lockGetWeekSchedule.daysMask(numToBinStr(daysMask), {state_change = true}))
  else
    log.info_with({hub_logs=true}, string.format("daysMask: null"))
    device:emit_event(lockGetWeekSchedule.daysMask("Null", {state_change = true}))
  end

  if startHour ~= nil then
    log.info_with({hub_logs=true}, string.format("startHour: %d", startHour))
    device:emit_event(lockGetWeekSchedule.startHour(tostring(startHour), {state_change = true}))
  else
    log.info_with({hub_logs=true}, string.format("startHour: null"))
    device:emit_event(lockGetWeekSchedule.startHour("Null", {state_change = true}))
  end

  if startMinute ~= nil then
    log.info_with({hub_logs=true}, string.format("startMinute: %d", startMinute))
    device:emit_event(lockGetWeekSchedule.startMinute(tostring(startMinute), {state_change = true}))
  else
    log.info_with({hub_logs=true}, string.format("startMinute: null"))
    device:emit_event(lockGetWeekSchedule.startMinute("Null", {state_change = true}))
  end

  if endHour ~= nil then
    log.info_with({hub_logs=true}, string.format("endHour: %d", endHour))
    device:emit_event(lockGetWeekSchedule.endHour(tostring(endHour), {state_change = true}))
  else
    log.info_with({hub_logs=true}, string.format("endHour: null"))
    device:emit_event(lockGetWeekSchedule.endHour("Null", {state_change = true}))
  end

  if endMinute ~= nil then
    log.info_with({hub_logs=true}, string.format("endMinute: %d", endMinute))
    device:emit_event(lockGetWeekSchedule.endMinute(tostring(endMinute), {state_change = true}))
  else
    log.info_with({hub_logs=true}, string.format("endMinute: null"))
    device:emit_event(lockGetWeekSchedule.endMinute("Null", {state_change = true}))
  end
end

----------------------------
-- Lock Add Year Schedule --
----------------------------
local function handle_add_year_schedule_set_user_index(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_add_year_schedule_set_user_index !!!!!!!!!!!!!"))

  local userIndex = command.args.userIndex
  log.info_with({hub_logs=true}, string.format("userIndex: %s", userIndex))
  device:emit_event(lockAddYearSchedule.userIndex(userIndex, {state_change = true}))
end

local function handle_add_year_schedule_set_schedule_index(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_add_year_schedule_set_schedule_index !!!!!!!!!!!!!"))

  local scheduleIndex = command.args.scheduleIndex
  log.info_with({hub_logs=true}, string.format("scheduleIndex: %s", scheduleIndex))
  device:emit_event(lockAddYearSchedule.scheduleIndex(scheduleIndex, {state_change = true}))
end

local function handle_add_year_schedule_set_start_time(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_add_year_schedule_set_start_time !!!!!!!!!!!!!"))

  local startTime = command.args.startTime
  log.info_with({hub_logs=true}, string.format("startTime: %s", startTime))
  device:emit_event(lockAddYearSchedule.startTime(startTime, {state_change = true}))
end

local function handle_add_year_schedule_set_end_time(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_add_year_schedule_set_end_time !!!!!!!!!!!!!"))

  local endTime = command.args.endTime
  log.info_with({hub_logs=true}, string.format("endTime: %s", endTime))
  device:emit_event(lockAddYearSchedule.endTime(endTime, {state_change = true}))
end

local function handle_add_year_schedule(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_add_week_schedule !!!!!!!!!!!!!"))
  
  local ep = device:component_to_endpoint(command.component)
  local userIndex = device:get_latest_state("main", lockAddYearScheduleID, lockAddYearSchedule.userIndex.NAME)
  userIndex = math.tointeger(userIndex)
  local scheduleIndex = device:get_latest_state("main", lockAddYearScheduleID, lockAddYearSchedule.scheduleIndex.NAME)
  scheduleIndex = math.tointeger(scheduleIndex)
  -- local startTime = device:get_latest_state("main", lockAddYearScheduleID, lockAddYearSchedule.startTime.NAME)
  -- local endTime = device:get_latest_state("main", lockAddYearScheduleID, lockAddYearSchedule.endTime.NAME)
  
  -- Temporary time
  local startTime = 1721746800
  local endTime = 1724425200

  log.info_with({hub_logs=true}, string.format("userIndex: %s, scheduleIndex: %s", userIndex, scheduleIndex))
  log.info_with({hub_logs=true}, string.format("startTime: %s, endTime: %s", startTime, endTime))

  device:send(
    DoorLock.server.commands.SetYearDaySchedule(
      device, ep,
      scheduleIndex, -- Year Day Schedule Index
      userIndex,     -- User Index
      startTime,     -- Local Start Time
      endTime        -- Local End Time
    )
  )
end

------------------------------
-- Lock Clear Year Schedule --
------------------------------
local function handle_clear_year_schedule_set_user_index(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_clear_year_schedule_set_user_index !!!!!!!!!!!!!"))

  local userIndex = command.args.userIndex
  log.info_with({hub_logs=true}, string.format("userIndex: %s", userIndex))
  device:emit_event(lockClearYearSchedule.userIndex(userIndex, {state_change = true}))
end

local function handle_clear_year_schedule_set_schedule_index(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_clear_year_schedule_set_schedule_index !!!!!!!!!!!!!"))

  local scheduleIndex = command.args.scheduleIndex
  log.info_with({hub_logs=true}, string.format("scheduleIndex: %s", scheduleIndex))
  device:emit_event(lockClearYearSchedule.scheduleIndex(scheduleIndex, {state_change = true}))
end

local function handle_clear_year_schedule(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_clear_year_schedule !!!!!!!!!!!!!"))
  
  local ep = device:component_to_endpoint(command.component)
  local userIndex = device:get_latest_state("main", lockClearYearScheduleID, lockClearYearSchedule.userIndex.NAME)
  userIndex = math.tointeger(userIndex)
  local scheduleIndex = device:get_latest_state("main", lockClearYearScheduleID, lockClearYearSchedule.scheduleIndex.NAME)
  scheduleIndex = math.tointeger(scheduleIndex)

  log.info_with({hub_logs=true}, string.format("userIndex: %s, scheduleIndex: %s", userIndex, scheduleIndex))

  device:send(
    DoorLock.server.commands.ClearYearDaySchedule(
      device, ep,
      scheduleIndex, -- Year Day Schedule Index
      userIndex      -- User Index
    )
  )
end

----------------------------
-- Lock Get Year Schedule --
----------------------------
local function handle_get_year_schedule_set_user_index(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_get_year_schedule_set_user_index !!!!!!!!!!!!!"))

  local userIndex = command.args.userIndex
  log.info_with({hub_logs=true}, string.format("userIndex: %s", userIndex))
  device:emit_event(lockGetYearSchedule.userIndex(userIndex, {state_change = true}))
end

local function handle_get_year_schedule_set_schedule_index(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_get_year_schedule_set_schedule_index !!!!!!!!!!!!!"))

  local scheduleIndex = command.args.scheduleIndex
  log.info_with({hub_logs=true}, string.format("scheduleIndex: %s", scheduleIndex))
  device:emit_event(lockGetYearSchedule.scheduleIndex(scheduleIndex, {state_change = true}))
end

local function handle_get_year_schedule(driver, device, command)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_get_year_schedule !!!!!!!!!!!!!"))
  
  local ep = device:component_to_endpoint(command.component)
  local userIndex = device:get_latest_state("main", lockGetYearScheduleID, lockGetYearSchedule.userIndex.NAME)
  userIndex = math.tointeger(userIndex)
  local scheduleIndex = device:get_latest_state("main", lockGetYearScheduleID, lockGetYearSchedule.scheduleIndex.NAME)
  scheduleIndex = math.tointeger(scheduleIndex)

  log.info_with({hub_logs=true}, string.format("userIndex: %s, scheduleIndex: %s", userIndex, scheduleIndex))

  device:send(
    DoorLock.server.commands.GetYearDaySchedule(
      device, ep,
      scheduleIndex, -- Year Day Schedule Index
      userIndex      -- User Index
    )
  )
end

------------------------------------
-- Get Year Day Schedule Response --
------------------------------------
local function get_year_day_schedule_response_handler(driver, device, ib, response)
  if ib.status ~= im.InteractionResponse.Status.SUCCESS then
    device.log.warn("Not taking action on GetYearDayScheduleResponse because failed status")
    return
  end

  local elements = ib.info_block.data.elements
  local status = elements.status.value
  local result = "Success"
  if status == DoorLock.types.DlStatus.FAILURE then
    result = "Failure"
  elseif status == DoorLock.types.DlStatus.DUPLICATE then
    result = "Duplicate"
  elseif status == DoorLock.types.DlStatus.OCCUPIED then
    result = "Occupied"
  elseif status == DoorLock.types.DlStatus.INVALID_FIELD then
    result = "Invalid Field"
  elseif status == DoorLock.types.DlStatus.RESOURCE_EXHAUSTED then
    result = "Resource Exhausted"
  elseif status == DoorLock.types.DlStatus.NOT_FOUND then
    result = "Not Found"
  end
  log.info_with({hub_logs=true}, string.format("status: %s", result))
  device:emit_event(lockGetYearSchedule.status(result, {state_change = true}))
  if status ~= DoorLock.types.DlStatus.SUCCESS then
    log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! get_year_day_schedule_response_handler: failure !!!!!!!!!!!!!"))
    return
  end

  local startTime = elements.loca_start_time.value
  local endTime = elements.loca_end_time.value

  if startTime ~= nil then
    log.info_with({hub_logs=true}, string.format("startTime: %d", startTime))
    device:emit_event(lockGetYearSchedule.startTime(tostring(startTime), {state_change = true}))
  else
    log.info_with({hub_logs=true}, string.format("startTime: null"))
    device:emit_event(lockGetYearSchedule.startTime("Null", {state_change = true}))
  end

  if endTime ~= nil then
    log.info_with({hub_logs=true}, string.format("endTime: %d", endTime))
    device:emit_event(lockGetYearSchedule.endTime(tostring(endTime), {state_change = true}))
  else
    log.info_with({hub_logs=true}, string.format("endTime: null"))
    device:emit_event(lockGetYearSchedule.endTime("Null", {state_change = true}))
  end
end

local function handle_refresh(driver, device, command)
  local req = DoorLock.attributes.LockState:read(device)
  device:send(req)
  device:set_field(lock_utils.BUSY_STATE, false, {persist = true})
end














local matter_lock_driver = {
  lifecycle_handlers = {
    init = device_init,
    added = device_added,
    doConfigure = do_configure,
  },
  matter_handlers = {
    attr = {
      [DoorLock.ID] = {
        [DoorLock.attributes.LockState.ID] = lock_state_handler,
        -- [DoorLock.attributes.LockType.ID] = lock_type_handler,
        -- [DoorLock.attributes.OperatingMode.ID] = operating_modes_handler,
        -- [DoorLock.attributes.AutoRelockTime.ID] = auto_relock_time_handler,
        -- [DoorLock.attributes.MaxPINCodeLength.ID] = max_pin_code_len_handler,
        -- [DoorLock.attributes.MinPINCodeLength.ID] = min_pin_code_len_handler,
        -- [DoorLock.attributes.NumberOfPINUsersSupported.ID] = num_pin_users_handler,
        -- [DoorLock.attributes.WrongCodeEntryLimit.ID] = wrong_code_entry_limit_handler,
        -- [DoorLock.attributes.UserCodeTemporaryDisableTime.ID] = user_code_temporary_disable_time_handler,
        -- [DoorLock.attributes.RequirePINforRemoteOperation.ID] = require_remote_pin_handler,
        -- [DoorLock.attributes.NumberOfTotalUsersSupported.ID] = num_total_users_handler,
        -- [DoorLock.attributes.NumberOfCredentialsSupportedPerUser.ID] = num_cred_handler,
        -- [DoorLock.attributes.CredentialRulesSupport.ID] = cred_rules_handler,
      }
    },
    event = {
      [DoorLock.ID] = {
        -- [DoorLock.events.DoorLockAlarm.ID] = door_lock_alarm_event_handler,
        [DoorLock.events.LockOperation.ID] = lock_op_event_handler,
        -- [DoorLock.events.LockOperationError.ID] = lock_op_err_event_handler,
        -- [DoorLock.events.LockUserChange.ID] = lock_user_change_event_handler,
      },
    },
    cmd_response = {
      [DoorLock.ID] = {
        [DoorLock.server.commands.SetUser.ID] = set_user_response_handler,
        [DoorLock.server.commands.ClearUser.ID] = clear_user_response_handler,
        [DoorLock.client.commands.GetUserResponse.ID] = get_user_response_handler,
        [DoorLock.client.commands.SetCredentialResponse.ID] = set_credential_response_handler,
        [DoorLock.server.commands.ClearCredential.ID] = clear_credential_response_handler,
        [DoorLock.client.commands.GetCredentialStatusResponse.ID] = get_credential_status_response_handler,
        [DoorLock.server.commands.SetWeekDaySchedule.ID] = set_week_day_schedule_handler,
        [DoorLock.server.commands.ClearWeekDaySchedule.ID] = clear_week_day_schedule_handler,
        [DoorLock.client.commands.GetWeekDayScheduleResponse.ID] = get_week_day_schedule_response_handler,
      },
    },
  },
  subscribed_attributes = {
    [capabilities.lock.ID] = {
      DoorLock.attributes.LockState
    },
    [lockWithPinID] = {
      DoorLock.attributes.LockState
    },
    -- [lockStatusID] = {
    --   DoorLock.attributes.LockState,
    --   DoorLock.attributes.LockType,
    --   DoorLock.attributes.OperatingMode,
    --   DoorLock.attributes.AutoRelockTime,
    -- },
    -- [lockStatusForPinID] = {
    --   DoorLock.attributes.MaxPINCodeLength,
    --   DoorLock.attributes.MinPINCodeLength,
    --   DoorLock.attributes.NumberOfPINUsersSupported,
    --   DoorLock.attributes.WrongCodeEntryLimit,
    --   DoorLock.attributes.UserCodeTemporaryDisableTime,
    --   DoorLock.attributes.RequirePINforRemoteOperation,
    -- },
    -- [lockStatusForUserID] = {
    --   DoorLock.attributes.NumberOfTotalUsersSupported,
    --   DoorLock.attributes.NumberOfCredentialsSupportedPerUser,
    --   DoorLock.attributes.CredentialRulesSupport,
    -- },
  },
  subscribed_events = {
    -- [lockStatusID] = {
    --   DoorLock.events.DoorLockAlarm,
    --   DoorLock.events.LockOperation,
    --   DoorLock.events.LockOperationError,
    -- },
    -- [lockStatusForUserID] = {
    --   DoorLock.events.LockUserChange,
    -- },
  },
  capability_handlers = {
    [capabilities.lock.ID] = {
      [capabilities.lock.commands.lock.NAME] = handle_lock,
      [capabilities.lock.commands.unlock.NAME] = handle_unlock,
    },
    [lockWithPinID] = {
      [lockWithPin.commands.setPin.NAME] = handle_lock_with_pin_set_pin,
      [lockWithPin.commands.lock.NAME] = handle_lock_with_pin,
      [lockWithPin.commands.unlock.NAME] = handle_unlock_with_pin,
    },
    [lockAddUserID] = {
      [lockAddUser.commands.setUserIndex.NAME] = handle_add_user_set_user_index,
      [lockAddUser.commands.setUserType.NAME] = handle_add_user_set_user_type,
      [lockAddUser.commands.addUser.NAME] = handle_add_user,
    },
    [lockModifyUserID] = {
      [lockModifyUser.commands.setUserIndex.NAME] = handle_modify_user_set_user_index,
      [lockModifyUser.commands.setUserStatus.NAME] = handle_modify_user_set_user_status,
      [lockModifyUser.commands.setUserType.NAME] = handle_modify_user_set_user_type,
      [lockModifyUser.commands.modifyUser.NAME] = handle_modify_user,
    },
    [lockClearUserID] = {
      [lockClearUser.commands.setUserIndex.NAME] = handle_clear_user_set_user_index,
      [lockClearUser.commands.clearUser.NAME] = handle_clear_user,
    },
    [lockGetUserID] = {
      [lockGetUser.commands.setUserIndex.NAME] = handle_get_user_set_user_index,
      [lockGetUser.commands.getUser.NAME] = handle_get_user,
    },
    [lockAddPinID] = {
      [lockAddPin.commands.setCredIndex.NAME] = handle_add_pin_set_cred_index,
      [lockAddPin.commands.setPin.NAME] = handle_add_pin_set_pin,
      [lockAddPin.commands.setUserIndex.NAME] = handle_add_pin_set_user_index,
      [lockAddPin.commands.setUserType.NAME] = handle_add_pin_set_user_type,
      [lockAddPin.commands.addPin.NAME] = handle_add_pin,
    },
    [lockModifyPinID] = {
      [lockModifyPin.commands.setUserIndex.NAME] = handle_modify_pin_set_user_index,
      [lockModifyPin.commands.setCredIndex.NAME] = handle_modify_pin_set_cred_index,
      [lockModifyPin.commands.setPin.NAME] = handle_modify_pin_set_pin,
      [lockModifyPin.commands.modifyPin.NAME] = handle_modify_pin,
    },
    [lockClearPinID] = {
      [lockClearPin.commands.setCredIndex.NAME] = handle_clear_pin_set_cred_index,
      [lockClearPin.commands.clearPin.NAME] = handle_clear_pin,
    },
    [lockGetPinID] = {
      [lockGetPin.commands.setCredIndex.NAME] = handle_get_pin_set_cred_index,
      [lockGetPin.commands.getPin.NAME] = handle_get_pin,
    },
    [lockAddWeekScheduleID] = {
      [lockAddWeekSchedule.commands.setUserIndex.NAME] = handle_add_week_schedule_set_user_index,
      [lockAddWeekSchedule.commands.setScheduleIndex.NAME] = handle_add_week_schedule_set_schedule_index,
      [lockAddWeekSchedule.commands.setDaysMask.NAME] = handle_add_week_schedule_set_days_mask,
      [lockAddWeekSchedule.commands.setStartHour.NAME] = handle_add_week_schedule_set_start_hour,
      [lockAddWeekSchedule.commands.setEndHour.NAME] = handle_add_week_schedule_set_end_hour,
      [lockAddWeekSchedule.commands.addWeekSchedule.NAME] = handle_add_week_schedule,
    },
    [lockClearWeekScheduleID] = {
      [lockClearWeekSchedule.commands.setUserIndex.NAME] = handle_clear_week_schedule_set_user_index,
      [lockClearWeekSchedule.commands.setScheduleIndex.NAME] = handle_clear_week_schedule_set_schedule_index,
      [lockClearWeekSchedule.commands.clearWeekSchedule.NAME] = handle_clear_week_schedule,
    },
    [lockGetWeekScheduleID] = {
      [lockGetWeekSchedule.commands.setUserIndex.NAME] = handle_get_week_schedule_set_user_index,
      [lockGetWeekSchedule.commands.setScheduleIndex.NAME] = handle_get_week_schedule_set_schedule_index,
      [lockGetWeekSchedule.commands.getWeekSchedule.NAME] = handle_get_week_schedule,
    },
    [lockAddYearScheduleID] = {
      [lockAddYearSchedule.commands.setUserIndex.NAME] = handle_add_year_schedule_set_user_index,
      [lockAddYearSchedule.commands.setScheduleIndex.NAME] = handle_add_year_schedule_set_schedule_index,
      [lockAddYearSchedule.commands.setStartTime.NAME] = handle_add_year_schedule_set_start_time,
      [lockAddYearSchedule.commands.setEndTime.NAME] = handle_add_year_schedule_set_end_time,
      [lockAddYearSchedule.commands.addYearSchedule.NAME] = handle_add_year_schedule,
    },
    [lockClearYearScheduleID] = {
      [lockClearYearSchedule.commands.setUserIndex.NAME] = handle_clear_year_schedule_set_user_index,
      [lockClearYearSchedule.commands.setScheduleIndex.NAME] = handle_clear_year_schedule_set_schedule_index,
      [lockClearYearSchedule.commands.clearYearSchedule.NAME] = handle_clear_year_schedule,
    },
    [lockGetYearScheduleID] = {
      [lockGetYearSchedule.commands.setUserIndex.NAME] = handle_get_year_schedule_set_user_index,
      [lockGetYearSchedule.commands.setScheduleIndex.NAME] = handle_get_year_schedule_set_schedule_index,
      [lockGetYearSchedule.commands.getYearSchedule.NAME] = handle_get_year_schedule,
    },
    [capabilities.refresh.ID] = {[capabilities.refresh.commands.refresh.NAME] = handle_refresh}
  },
  supported_capabilities = {
    capabilities.lock,
    lockWithPin,
    lockAddUser,
    lockModifyUser,
    lockClearUser,
    lockGetUser,
    lockAddPin,
    lockModifyPin,
    lockClearPin,
    lockGetPin,
    lockAddWeekSchedule,
    lockClearWeekSchedule,
    lockGetWeekSchedule,
    lockAddYearSchedule,
    lockClearYearSchedule,
    lockGetYearSchedule,
    -- lockStatus,
    -- lockStatusForPin,
    -- lockStatusForUser,
  },
}

-----------------------------------------------------------------------------------------------------------------------------
-- Driver Initialization
-----------------------------------------------------------------------------------------------------------------------------
local matter_driver = MatterDriver("matter-lock", matter_lock_driver)
matter_driver:run()