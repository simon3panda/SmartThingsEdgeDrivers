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

-- local INITIAL_COTA_INDEX = 1

local DoorLock = clusters.DoorLock

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

-- local lockPinCodeID = "insideimage13541.lockPinCode10"
-- local lockPinCode = capabilities[lockPinCodeID]
-- local lockStatusID = "insideimage13541.lockStatus1"
-- local lockStatus = capabilities[lockStatusID]
-- local lockStatusForPinID = "insideimage13541.lockStatusForPin1"
-- local lockStatusForPin = capabilities[lockStatusForPinID]
-- local lockStatusForUserID = "insideimage13541.lockStatusForUser3"
-- local lockStatusForUser = capabilities[lockStatusForUserID]
-- local lockGetCredID = "insideimage13541.lockGetCredentialStatus3"
-- local lockGetCred = capabilities[lockGetCredID]

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

  -- local opTypeTable = {
  --   lockSetUser.dataOperationType.add.NAME,
  --   lockSetUser.dataOperationType.modify.NAME,
  -- }
  -- device:emit_event_for_endpoint(ep, lockSetUser.supportedDataOperationType(opTypeTable))
  -- device:emit_event_for_endpoint(ep, lockSetUser.dataOperationType(lockSetUser.dataOperationType.select.NAME, {visibility = {displayed = false}}))
  -- device:emit_event_for_endpoint(ep, lockSetCred.supportedDataOperationType(opTypeTable))
  -- device:emit_event_for_endpoint(ep, lockSetCred.dataOperationType(lockSetCred.dataOperationType.select.NAME, {visibility = {displayed = false}}))

  -- local userType = lockSetUser.userType
  -- local userTypeTable = {
  --   userType.unrestricted.NAME,
  --   userType.yearDayScheduleUser.NAME,
  --   userType.weekDayScheduleUser.NAME,
  --   userType.programmingUser.NAME,
  --   userType.nonAccessUser.NAME,
  --   userType.forcedUser.NAME,
  --   userType.disposableUser.NAME,
  --   userType.expiringUser.NAME,
  --   userType.scheduleRestrictedUser.NAME,
  --   userType.remoteOnlyUser.NAME,
  -- }
  -- device:emit_event_for_endpoint(ep, lockSetUser.supportedUserType(userTypeTable))
  -- device:emit_event_for_endpoint(ep, lockSetUser.userType(lockSetUser.userType.select.NAME, {visibility = {displayed = false}}))
  -- device:emit_event_for_endpoint(ep, lockSetCred.supportedUserType(userTypeTable))
  -- device:emit_event_for_endpoint(ep, lockSetCred.userType(lockSetCred.userType.select.NAME, {visibility = {displayed = false}}))

  -- local credType = lockSetCred.credType
  -- local credTypeTable = {
  --   credType.programmingPin.NAME,
  --   credType.pin.NAME,
  --   credType.rfid.NAME,
  --   credType.fingerprint.NAME,
  --   credType.fingerVein.NAME,
  --   credType.face.NAME,
  -- }
  -- device:emit_event_for_endpoint(ep, lockSetCred.supportedCredType(credTypeTable))
  -- device:emit_event_for_endpoint(ep, lockSetCred.credType(lockSetCred.credType.select.NAME, {visibility = {displayed = false}}))
  -- device:emit_event_for_endpoint(ep, lockGetCred.supportedCredType(credTypeTable))
  -- device:emit_event_for_endpoint(ep, lockGetCred.credType(lockSetCred.credType.select.NAME, {visibility = {displayed = false}}))

  -- User Data Hard coding
  device:send(DoorLock.server.commands.SetUser(device, ep, 0, 1, nil, nil, nil, nil, nil))
  local credential = {credential_type = 1, credential_index = 1}
  device:send(DoorLock.server.commands.SetCredential(device, ep, 0, credential, "\x30\x33\x35\x37\x39\x30", 1, nil, nil))
end














 -- Custom Driver for testing
-- Matter Handler
-- for Lock Status Capability
local function lock_state_handler(driver, device, ib, response)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! lock_state_handler: %s !!!!!!!!!!!!!", ib.data.value))
  local LockState = DoorLock.attributes.LockState
  if ib.data.value == LockState.NOT_FULLY_LOCKED then
    -- device:emit_event(lockStatus.lockState.notFullyLocked())
    device:emit_event(capabilities.lock.lock.unknown())
  elseif ib.data.value == LockState.LOCKED then
    -- device:emit_event(lockStatus.lockState.locked())
    device:emit_event(capabilities.lock.lock.locked())
  elseif ib.data.value == LockState.UNLOCKED then
    -- device:emit_event(lockStatus.lockState.unlocked())
    device:emit_event(capabilities.lock.lock.unlocked())
  elseif ib.data.value == LockState.UNLATCHED then
    -- device:emit_event(lockStatus.lockState.unlatched())
    device:emit_event(capabilities.lock.lock.locked())
  else
    -- device:emit_event(lockStatus.lockState.locked())
    device:emit_event(capabilities.lock.lock.locked())
  end
end

-- local function lock_type_handler(driver, device, ib, response)
--   log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! lock_type_handler: %d !!!!!!!!!!!!!", ib.data.value))
--   if ib.data.value == DoorLock.types.DlLockType.DEAD_BOLT then
--     device:emit_event(lockStatus.lockType.deadBolt())
--   elseif ib.data.value == DoorLock.types.DlLockType.MAGNETIC then
--     device:emit_event(lockStatus.lockType.magnetic())
--   elseif ib.data.value == DoorLock.types.DlLockType.OTHER then
--     device:emit_event(lockStatus.lockType.other())
--   elseif ib.data.value == DoorLock.types.DlLockType.MORTISE then
--     device:emit_event(lockStatus.lockType.mortise())
--   elseif ib.data.value == DoorLock.types.DlLockType.RIM then
--     device:emit_event(lockStatus.lockType.rim())
--   elseif ib.data.value == DoorLock.types.DlLockType.LATCH_BOLT then
--     device:emit_event(lockStatus.lockType.latchBolt())
--   elseif ib.data.value == DoorLock.types.DlLockType.CYLINDRICAL_LOCK then
--     device:emit_event(lockStatus.lockType.cylindricalLock())
--   elseif ib.data.value == DoorLock.types.DlLockType.TUBULAR_LOCK then
--     device:emit_event(lockStatus.lockType.tubularLock())
--   elseif ib.data.value == DoorLock.types.DlLockType.INTERCONNECTED_LOCK then
--     device:emit_event(lockStatus.lockType.interconnectedLock())
--   elseif ib.data.value == DoorLock.types.DlLockType.DEAD_LATCH then
--     device:emit_event(lockStatus.lockType.deadLatch())
--   elseif ib.data.value == DoorLock.types.DlLockType.DOOR_FURNITURE then
--     device:emit_event(lockStatus.lockType.doorFurniture())
--   elseif ib.data.value == DoorLock.types.DlLockType.EUROCYLINDER then
--     device:emit_event(lockStatus.lockType.eurocylinder())
--   else
--     device:emit_event(lockStatus.lockType.other())
--   end
-- end

-- local function operating_modes_handler(driver, device, ib, response)
--   log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! operating_modes_handler: %d !!!!!!!!!!!!!", ib.data.value))
--   if ib.data.value == DoorLock.types.OperatingModeEnum.NORMAL then
--     device:emit_event(lockStatus.lockOperatingMode.normal())
--   elseif ib.data.value == DoorLock.types.OperatingModeEnum.VACATION then
--     device:emit_event(lockStatus.lockOperatingMode.vacation())
--   elseif ib.data.value == DoorLock.types.OperatingModeEnum.PRIVACY then
--     device:emit_event(lockStatus.lockOperatingMode.privacy())
--   elseif ib.data.value == DoorLock.types.OperatingModeEnum.NO_REMOTE_LOCK_UNLOCK then
--     device:emit_event(lockStatus.lockOperatingMode.noRemoteLockUnlock())
--   elseif ib.data.value == DoorLock.types.OperatingModeEnum.PASSAGE then
--     device:emit_event(lockStatus.lockOperatingMode.passage())
--   else
--     device:emit_event(lockStatus.lockOperatingMode.normal())
--   end
-- end

-- local function auto_relock_time_handler(driver, device, ib, response)
--   log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! auto_relock_time_handler: %d !!!!!!!!!!!!!", ib.data.value))
--   device:emit_event(lockStatus.autoRelockTime(ib.data.value, {visibility = {displayed = false}}))
-- end

-- local function door_lock_alarm_event_handler(driver, device, ib, response)
--   local alarmCode = DoorLock.types.AlarmCodeEnum
--   local event = ib.data.elements.alarm_code
--   log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! door_lock_alarm_event_handler: %s !!!!!!!!!!!!!", event))
--   if event.value == alarmCode.LOCK_JAMMED then
--     device:emit_event(lockStatus.doorLockAlarm.lockJammed())
--   elseif event.value == alarmCode.LOCK_FACTORY_RESET then
--     device:emit_event(lockStatus.doorLockAlarm.lockFactoryReset())
--   elseif event.value == alarmCode.LOCK_RADIO_POWER_CYCLED then
--     device:emit_event(lockStatus.doorLockAlarm.lockRadioPowerCycled())
--   elseif event.value == alarmCode.WRONG_CODE_ENTRY_LIMIT then
--     device:emit_event(lockStatus.doorLockAlarm.wrongCodeEntryLimit())
--   elseif event.value == alarmCode.FRONT_ESCEUTCHEON_REMOVED then
--     device:emit_event(lockStatus.doorLockAlarm.frontEsceutcheonRemoved())
--   elseif event.value == alarmCode.DOOR_FORCED_OPEN then
--     device:emit_event(lockStatus.doorLockAlarm.doorForcedOpen())
--   elseif event.value == alarmCode.DOOR_AJAR then
--     device:emit_event(lockStatus.doorLockAlarm.doorAjar())
--   elseif event.value == alarmCode.FORCED_USER then
--     device:emit_event(lockStatus.doorLockAlarm.forcedUser())
--   end
-- end

-- local function lock_op_event_handler(driver, device, ib, response)
--   local opType = DoorLock.types.LockOperationTypeEnum
--   local event = ib.data.elements.lock_operation_type
--   log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! lock_op_event_handler: %s !!!!!!!!!!!!!", event))
--   if event.value == opType.LOCK then
--     device:emit_event(lockStatus.lockOperationEvent.lockEvent())
--   elseif event.value == opType.UNLOCK then
--     device:emit_event(lockStatus.lockOperationEvent.unlockEvent())
--   elseif event.value == opType.NON_ACCESS_USER_EVENT then
--     device:emit_event(lockStatus.lockOperationEvent.nonAccessUserEvent())
--   elseif event.value == opType.FORCED_USER_EVENT then
--     device:emit_event(lockStatus.lockOperationEvent.forcedUserEvent())
--   elseif event.value == opType.UNLATCH then
--     device:emit_event(lockStatus.lockOperationEvent.unlatchEvent())
--   end
-- end

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
-- local function handle_lock_with_pin_code(driver, device, command)
--   log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_lock_with_pin_code: %s !!!!!!!!!!!!!", command.args.pinCode))
--   local ep = device:component_to_endpoint(command.component)
--   device:send(DoorLock.server.commands.LockDoor(device, ep, command.args.pinCode))
--   device:emit_event(lockPinCode.lockPinCode("", {visibility = {displayed = false}}))
--   device:emit_event(lockPinCode.lockPinCode(command.args.pinCode, {visibility = {displayed = false}}))
-- end

-- local function handle_unlock_with_pin_code(driver, device, command)
--   log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! handle_unlock_with_pin_code: %s !!!!!!!!!!!!!", command.args.pinCode))
--   local ep = device:component_to_endpoint(command.component)
--   device:send(DoorLock.server.commands.UnlockDoor(device, ep, command.args.pinCode))
--   device:emit_event(lockPinCode.unlockPinCode("", {visibility = {displayed = false}}))
--   device:emit_event(lockPinCode.unlockPinCode(command.args.pinCode, {visibility = {displayed = false}}))
-- end

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
  for typeInteger, typeString in pairs(USER_TYPE_MAP) do
    if userType == typeString then
      userType = typeInteger
      break
    end
  end
  log.info_with({hub_logs=true}, string.format("userIndex: %s, userType: %s", userIndex, userType))

  device:send(
    DoorLock.server.commands.SetUser(
      device, ep,
      0,          -- Operation Type: Add(0), Modify(2)
      userIndex,  -- User Index
      nil,        -- User Name
      nil,        -- Unique ID
      nil,        -- User Status
      userType,   -- User Type
      nil         -- Credential Rule
    )
  )
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

  device:send(
    DoorLock.server.commands.SetUser(
      device, ep,
      2,          -- Operation Type: Add(0), Modify(2)
      userIndex,  -- User Index
      nil,        -- User Name
      nil,        -- Unique ID
      userStatus, -- User Status
      nil,        -- User Type
      nil         -- Credential Rule
    )
  )
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
  
  device:send(DoorLock.server.commands.ClearUser(device, ep, userIndex))
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

  local credential = {credential_type = DoorLock.types.CredentialTypeEnum.PIN, credential_index = credIndex}
  device:send(
    DoorLock.server.commands.SetCredential(
      device, ep,
      0,           -- Data Operation Type: Add(0), Modify(2)
      credential,  -- Credential
      pin,         -- Credential Data
      userIndex,   -- User Index
      nil,         -- User Status
      nil     -- User Type
    )
  )
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
local function set_credential_response_handler(driver, device, ib, response)
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! set_credential_response_handler !!!!!!!!!!!!!"))

  local elements = ib.info_block.data.elements
  if ib.status ~= im.InteractionResponse.Status.SUCCESS then
    device.log.error("Failed to set pin for device")
    return
  end

  local ep = find_default_endpoint(device, DoorLock.ID)
  if elements.status.value == 0 then -- Success
    log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! set_credential_response_handler: succcess !!!!!!!!!!!!!"))
    return
  end

  -- @field public byte_length number 1
  -- @field public SUCCESS number 0
  -- @field public FAILURE number 1
  -- @field public DUPLICATE number 2
  -- @field public OCCUPIED number 3
  -- @field public INVALID_FIELD number 133
  -- @field public RESOURCE_EXHAUSTED number 137
  -- @field public NOT_FOUND number 139
 
  log.info_with({hub_logs=true}, string.format("!!!!!!!!!!!!!!! set_credential_response_handler: failure !!!!!!!!!!!!!"))
  local result = "Failure"
  if elements.status.value == DoorLock.types.DlStatus.FAILURE then
    result = "Failure"
  elseif elements.status.value == DoorLock.types.DlStatus.DUPLICATE then
    result = "Duplicate"
  elseif elements.status.value == DoorLock.types.DlStatus.OCCUPIED then
    result = "Occupied"
  elseif elements.status.value == DoorLock.types.DlStatus.INVALID_FIELD then
    result = "Invalid Field"
  elseif elements.status.value == DoorLock.types.DlStatus.RESOURCE_EXHAUSTED then
    result = "Resource Exhausted"
  elseif elements.status.value == DoorLock.types.DlStatus.NOT_FOUND then
    result = "Not Found"
  end
  log.info_with({hub_logs=true}, string.format("Result: %s", result))
  log.info_with({hub_logs=true}, string.format("Next Credential Index %s", elements.next_credential_index.value))
end

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

  device:send(DoorLock.server.commands.ClearCredential(device, ep, credential))
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

local function handle_refresh(driver, device, command)
  local req = DoorLock.attributes.LockState:read(device)
  device:send(req)
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
    -- event = {
    --   [DoorLock.ID] = {
    --     [DoorLock.events.DoorLockAlarm.ID] = door_lock_alarm_event_handler,
    --     [DoorLock.events.LockOperation.ID] = lock_op_event_handler,
    --     [DoorLock.events.LockOperationError.ID] = lock_op_err_event_handler,
    --     [DoorLock.events.LockUserChange.ID] = lock_user_change_event_handler,
    --   },
    -- },
    cmd_response = {
      [DoorLock.ID] = {
        [DoorLock.client.commands.GetUserResponse.ID] = get_user_response_handler,
        [DoorLock.client.commands.SetCredentialResponse.ID] = set_credential_response_handler,
        [DoorLock.client.commands.GetCredentialStatusResponse.ID] = get_credential_status_response_handler,
      },
    },
  },
  subscribed_attributes = {
    [capabilities.lock.ID] = {DoorLock.attributes.LockState},
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
    -- [lockPinCodeID] = {
    --   [lockPinCode.commands.lockWithPinCode.NAME] = handle_lock_with_pin_code,
    --   [lockPinCode.commands.unlockWithPinCode.NAME] = handle_unlock_with_pin_code,
    -- },
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
    [capabilities.refresh.ID] = {[capabilities.refresh.commands.refresh.NAME] = handle_refresh}
  },
  supported_capabilities = {
    capabilities.lock,
    -- lockPinCode,
    lockAddUser,
    lockModifyUser,
    lockClearUser,
    lockGetUser,
    lockAddPin,
    lockModifyPin,
    lockClearPin,
    lockGetPin,
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