#!/usr/bin/lua
-- SPDX-License-Identifier: GPL-2.0-only
-- Derived from fanchmwrt/fanchmwrt package/fcm/fwxd/files/rule_manager.lua.
-- Copyright (C) 2026 destan19 <www.fanchmwrt.com>

local ubus = require "ubus"
local os = require "os"
local io = require "io"

local CHECK_INTERVAL = 10  
local LOG_FILE = "/tmp/log/rule_manager.log" 
local SINGLE_MAC_FILTER_RULE_ID = 101  

local APPFILTER_STATE_FILE = "/tmp/appfilter_rules_state"
local MACFILTER_STATE_FILE = "/tmp/macfilter_rules_state"
local APPFILTER_WHITELIST_STATE_FILE = "/tmp/appfilter_whitelist_state"
local MACFILTER_WHITELIST_STATE_FILE = "/tmp/macfilter_whitelist_state"

local appfilter_rules_state = {} 
local macfilter_rules_state = {}

local appfilter_enable_state = nil
local macfilter_enable_state = nil
local record_enable_state = nil  
local rulesd_config = nil
local appfilter_whitelist_applied = nil
local macfilter_whitelist_applied = nil

local function core_call(method, payload)
    local conn = ubus.connect()
    if not conn then
        return nil, "ubus_connect_failed"
    end
    local ok, response = pcall(function()
        return conn:call("dreamingwrt", method, payload or {})
    end)
    conn:close()
    if not ok or type(response) ~= "table" then
        return nil, ok and "invalid_response" or tostring(response)
    end
    if response.code and tonumber(response.code) ~= 2000 then
        return nil, "core_error_" .. tostring(response.code)
    end
    return response.data or response
end

local function ensure_log_dir()
    os.execute(string.format("mkdir -p %s", string.match(LOG_FILE, "^(.*)/")))
end

local function log(message)
    ensure_log_dir()
    local timestamp = os.date("%Y-%m-%d %H:%M:%S")
    local log_msg = string.format("[%s] %s\n", timestamp, message)
	-- for debug
    --local file = io.open(LOG_FILE, "a")
    --if file then
    --   file:write(log_msg)
    --  file:close()
    --end
    print(log_msg)
end

local function get_current_time_info()
    local now = os.time()
    local date = os.date("*t", now)
    
    local weekday = date.wday - 1
    
    local current_minutes = date.hour * 60 + date.min
    
    return {
        weekday = weekday,
        hour = date.hour,
        min = date.min,
        minutes = current_minutes
    }
end

local function parse_time(time_str)
    if not time_str or time_str == "" then
        return nil
    end
    
    local hour, min = time_str:match("(%d+):(%d+)")
    if hour and min then
        return tonumber(hour) * 60 + tonumber(min)
    end
    return nil
end

local function is_time_in_range(time_rules, current_info)
    if not time_rules or #time_rules == 0 then
        return false
    end
    
    for _, time_rule in ipairs(time_rules) do
        if time_rule.weekdays and time_rule.start_time and time_rule.end_time then
            local weekday_match = false
            for _, wd in ipairs(time_rule.weekdays) do
                if wd == current_info.weekday then
                    weekday_match = true
                    break
                end
            end
            
            if weekday_match then
                local start_minutes = parse_time(time_rule.start_time)
                local end_minutes = parse_time(time_rule.end_time)
                
                if start_minutes and end_minutes then
                    if start_minutes <= end_minutes then
                        if current_info.minutes >= start_minutes and current_info.minutes <= end_minutes then
                            return true
                        end
                    else
                        if current_info.minutes >= start_minutes or current_info.minutes <= end_minutes then
                            return true
                        end
                    end
                end
            end
        end
    end
    
    return false
end

local function write_to_dev_jmx(json_str)
    local dev_file = "/dev/jmx"
    local check_cmd = string.format('test -e %s', dev_file)
    local check_result = os.execute(check_cmd)
    if check_result ~= 0 then
        log(string.format("WARNING: Device file %s does not exist, skipping", dev_file))
        return false
    end
    
    local file = io.open(dev_file, "w")
    if not file then
        log(string.format("ERROR: Failed to open %s for writing", dev_file))
        return false
    end
    
    local write_ok, write_err = file:write(json_str)
    local close_ok, close_err = file:close()
    if not write_ok or not close_ok then
        log(string.format("ERROR: Failed to write %s: %s", dev_file,
            tostring(write_err or close_err or "kernel_write_rejected")))
        return false
    end
    return true
end

local function delete_appfilter_rule(rule_id)
    log(string.format("AppFilter: Deleting rule %d", rule_id))
    local json_str = string.format('{"api":"del_app_filter_rule","data":{"rule_id":%d}}', rule_id)
    if write_to_dev_jmx(json_str) then
        log(string.format("AppFilter: Rule %d deleted successfully", rule_id))
        return true
    else
        log(string.format("AppFilter: Rule %d delete failed", rule_id))
        return false
    end
end

local function create_appfilter_rule(rule_id)
    log(string.format("AppFilter: Creating rule %d", rule_id))
    local json_str = string.format('{"api":"add_app_filter_rule","data":{"rule_id":%d}}', rule_id)
    if write_to_dev_jmx(json_str) then
        log(string.format("AppFilter: Rule %d created successfully", rule_id))
        return true
    else
        log(string.format("AppFilter: Rule %d create failed", rule_id))
        return false
    end
end


local function set_appfilter_rule_mac_list(rule_id, mac_list)
    log(string.format("AppFilter: Setting MAC list for rule %d, count=%d", rule_id, #mac_list))
    
    local mac_array_str = ""
    if #mac_list > 0 then
        local mac_strs = {}
        for _, mac in ipairs(mac_list) do
            table.insert(mac_strs, string.format('"%s"', mac))
        end
        mac_array_str = "[" .. table.concat(mac_strs, ",") .. "]"
    else
        mac_array_str = "[]"
    end
    
    local json_str = string.format('{"api":"mod_app_filter_rule","data":{"rule_id":%d,"mac_action":1,"mac_list":%s}}', 
        rule_id, mac_array_str)
    if write_to_dev_jmx(json_str) then
        log(string.format("AppFilter: MAC list for rule %d set successfully", rule_id))
        return true
    else
        log(string.format("AppFilter: MAC list for rule %d set failed", rule_id))
        return false
    end
end

local function set_appfilter_rule_app_id_list(rule_id, app_id_list)
    log(string.format("AppFilter: Setting App ID list for rule %d, count=%d", rule_id, #app_id_list))
    
    local app_id_array_str = ""
    if #app_id_list > 0 then
        local app_id_strs = {}
        for _, app_id in ipairs(app_id_list) do
            local numeric_id = tonumber(app_id)
            if not numeric_id or numeric_id <= 0 or numeric_id ~= math.floor(numeric_id) then
                log(string.format("ERROR: Invalid App ID for rule %d: %s", rule_id, tostring(app_id)))
                return false
            end
            table.insert(app_id_strs, tostring(numeric_id))
        end 
        app_id_array_str = "[" .. table.concat(app_id_strs, ",") .. "]"
    else
        app_id_array_str = "[]"
    end
    
    local json_str = string.format('{"api":"mod_app_filter_rule","data":{"rule_id":%d,"app_action":1,"app_id_list":%s}}', 
        rule_id, app_id_array_str)
    if write_to_dev_jmx(json_str) then
        log(string.format("AppFilter: App ID list for rule %d set successfully", rule_id))
        return true
    else
        log(string.format("AppFilter: App ID list for rule %d set failed", rule_id))
        return false
    end
end

local function set_appfilter_rule_filter_quic(rule_id, filter_quic)
    local filter_quic_value = tonumber(filter_quic) or 0
    if filter_quic_value ~= 1 then
        filter_quic_value = 0
    end

    log(string.format("AppFilter: Setting filter_quic for rule %d, value=%d", rule_id, filter_quic_value))
    local json_str = string.format('{"api":"mod_app_filter_rule","data":{"rule_id":%d,"filter_quic":%d}}',
        rule_id, filter_quic_value)
    if write_to_dev_jmx(json_str) then
        log(string.format("AppFilter: filter_quic for rule %d set successfully", rule_id))
        return true
    else
        log(string.format("AppFilter: filter_quic for rule %d set failed", rule_id))
        return false
    end
end

local function apply_macfilter_rule(rule_id, enable)
    log(string.format("MACFilter: apply_macfilter_rule called but enable field is no longer sent to kernel"))
    return true
end

local function create_macfilter_rule(rule_id)
    log(string.format("MACFilter: Creating rule %d", rule_id))
    local json_str = string.format('{"api":"add_mac_filter_rule","data":{"rule_id":%d}}', rule_id)
    if write_to_dev_jmx(json_str) then
        log(string.format("MACFilter: Rule %d created successfully", rule_id))
        return true
    else
        log(string.format("MACFilter: Rule %d create failed", rule_id))
        return false
    end
end

local function delete_macfilter_rule(rule_id)
    log(string.format("MACFilter: Deleting rule %d", rule_id))
    local json_str = string.format('{"api":"del_mac_filter_rule","data":{"rule_id":%d}}', rule_id)
    if write_to_dev_jmx(json_str) then
        log(string.format("MACFilter: Rule %d deleted successfully", rule_id))
        return true
    else
        log(string.format("MACFilter: Rule %d delete failed", rule_id))
        return false
    end
end

local function set_macfilter_rule_mac_list(rule_id, mac_list)
    log(string.format("MACFilter: Setting MAC list for rule %d, count=%d", rule_id, #mac_list))
    
    local clear_json = string.format('{"api":"mod_mac_filter_rule","data":{"rule_id":%d,"mac_action":0}}', rule_id)
    if not write_to_dev_jmx(clear_json) then
        log(string.format("MACFilter: Failed to clear MAC list for rule %d", rule_id))
        return false
    end
    
    if #mac_list == 0 then
        log(string.format("MACFilter: MAC list for rule %d cleared (empty list, no MACs to set)", rule_id))
        return true
    end
    
    local mac_strs = {}
    for _, mac in ipairs(mac_list) do
        table.insert(mac_strs, string.format('"%s"', mac))
    end
    local mac_array_str = "[" .. table.concat(mac_strs, ",") .. "]"
    
    local json_str = string.format('{"api":"mod_mac_filter_rule","data":{"rule_id":%d,"mac_action":1,"mac_list":%s}}', 
        rule_id, mac_array_str)
    if write_to_dev_jmx(json_str) then
        log(string.format("MACFilter: MAC list for rule %d set successfully", rule_id))
        return true
    else
        log(string.format("MACFilter: MAC list for rule %d set failed", rule_id))
        return false
    end
end

local function parse_legacy_time_rules(value)
    local parsed = {}
    local values = type(value) == "table" and value or {value}
    for _, raw in ipairs(values) do
        local weekdays, start_time, end_time = {}, nil, nil
        for part in tostring(raw or ""):gmatch("[^,]+") do
            if part:match(":") then
                if not start_time then start_time = part else end_time = part end
            else
                local weekday = tonumber(part)
                if weekday then table.insert(weekdays, weekday) end
            end
        end
        if start_time and end_time and #weekdays > 0 then
            table.insert(parsed, {weekdays = weekdays, start_time = start_time, end_time = end_time})
        end
    end
    return parsed
end

local function legacy_uci_payload()
    local uci = require "uci"
    local cursor = uci.cursor()
    local payload = {app_rules = {}, mac_rules = {}, app_whitelist = {}, mac_whitelist = {}}
    cursor:foreach("appfilter", "rule", function(section)
        local runtime_id = tonumber(section.id) or 0
        local app_ids = type(section.app_id) == "table" and section.app_id or {section.app_id}
        local clean_ids = {}
        for _, app_id in ipairs(app_ids) do if app_id and app_id ~= "" then table.insert(clean_ids, tostring(app_id)) end end
        table.insert(payload.app_rules, {
            id = "legacy_app_" .. tostring(runtime_id), runtime_rule_id = runtime_id,
            name = section.name or ("App rule " .. tostring(runtime_id)), enabled = tonumber(section.enabled) or 1,
            priority = runtime_id, source = section.user_mac and section.user_mac ~= "" and section.user_mac or "any",
            schedule = parse_legacy_time_rules(section.time_rule), app_ids = clean_ids, apps = {},
            destination = "any", action = "block", filter_quic = tonumber(section.filter_quic) or 0
        })
    end)
    cursor:foreach("macfilter", "rule", function(section)
        local runtime_id = tonumber(section.id) or 0
        table.insert(payload.mac_rules, {
            id = "legacy_mac_" .. tostring(runtime_id), runtime_rule_id = runtime_id,
            name = section.name or ("MAC rule " .. tostring(runtime_id)), enabled = tonumber(section.enabled) or 1,
            priority = runtime_id, source = tonumber(section.mode) == 2 and (section.user_mac or "") or "any",
            schedule = parse_legacy_time_rules(section.time_rule), mode = "deny", mac = section.user_mac or "",
            terminal_name = section.user_name or ""
        })
    end)
    cursor:foreach("appfilter_whitelist", "whitelist_mac", function(section)
        if section.mac and section.mac ~= "" then table.insert(payload.app_whitelist, section.mac) end
    end)
    cursor:foreach("macfilter_whitelist", "whitelist_mac", function(section)
        if section.mac and section.mac ~= "" then table.insert(payload.mac_whitelist, section.mac) end
    end)
    cursor:unload("appfilter"); cursor:unload("macfilter"); cursor:unload("appfilter_whitelist")
    cursor:unload("macfilter_whitelist")
    return payload
end

local function refresh_rulesd_config()
    local data, err = core_call("rulesd_config_get")
    if not data then return false, err end
    if not data.migration or data.migration.status ~= "done" then
        local migrated, migrate_err = core_call("rulesd_config_migrate", legacy_uci_payload())
        if not migrated then return false, migrate_err end
        data, err = core_call("rulesd_config_get")
        if not data then return false, err end
    end
    rulesd_config = data
    local function runtime_id(rule, salt, reserved, used)
        local configured = tonumber(rule.id)
        local candidate = configured
        if not candidate or candidate <= 0 or candidate == reserved then
            candidate = salt
            for i = 1, #(rule.config_id or "") do
                candidate = (candidate * 33 + (rule.config_id or ""):byte(i)) % 900000
            end
            candidate = candidate + 1000
        end
        while candidate == reserved or used[candidate] do candidate = candidate + 1 end
        used[candidate] = true
        return candidate
    end
    local app_ids, mac_ids = {}, {}
    for _, rule in ipairs(rulesd_config.app_rules or {}) do rule.id = runtime_id(rule, 17, -1, app_ids) end
    for _, rule in ipairs(rulesd_config.mac_rules or {}) do rule.id = runtime_id(rule, 29, SINGLE_MAC_FILTER_RULE_ID, mac_ids) end
    return true
end

local function load_appfilter_rules()
    local rules = rulesd_config and rulesd_config.app_rules or {}
    log(string.format("Loaded %d AppFilter rules from config.db", #rules))
    return rules
end

local function load_macfilter_rules()
    local rules = rulesd_config and rulesd_config.mac_rules or {}
    log(string.format("Loaded %d MACFilter rules from config.db", #rules))
    return rules
end

local function init_single_mac_rule()
    if create_macfilter_rule(SINGLE_MAC_FILTER_RULE_ID) then
        log("Single-user MACFilter rule initialized successfully")
        return true
    else
        log("Single-user MACFilter rule initialization failed")
        return false
    end
end

local function process_appfilter_rules(current_info)
    log(string.format("=== Processing AppFilter rules (time: %02d:%02d, weekday: %d) ===", 
        current_info.hour, current_info.min, current_info.weekday))
    
    local rules = load_appfilter_rules()
    
    for _, rule in ipairs(rules) do
        local time_match = is_time_in_range(rule.time_rules, current_info)
        local should_active = (rule.enabled == 1) and time_match
        local current_state = appfilter_rules_state[rule.id]
        local is_active = current_state and current_state.active or false
        
        log(string.format("AppFilter rule %d (%s): enabled=%d, time_match=%s, should_active=%s, is_active=%s", 
            rule.id, rule.name, rule.enabled, tostring(time_match), tostring(should_active), tostring(is_active)))
        
        if should_active then
            local mac_list = {}
            if rule.mode == 2 and rule.user_mac and rule.user_mac ~= "" then
                table.insert(mac_list, rule.user_mac)
            elseif rule.mode == 1 then
            end
            
            local app_id_list = rule.app_ids or {}
            
            local config_changed = false
            if not current_state then
                config_changed = true
            else
                if #mac_list ~= (current_state.mac_list and #current_state.mac_list or 0) then
                    config_changed = true
                else
                    local old_mac_set = {}
                    if current_state.mac_list then
                        for _, mac in ipairs(current_state.mac_list) do
                            old_mac_set[mac] = true
                        end
                    end
                    for _, mac in ipairs(mac_list) do
                        if not old_mac_set[mac] then
                            config_changed = true
                            break
                        end
                    end
                end
                
                if not config_changed then
                    if #app_id_list ~= (current_state.app_id_list and #current_state.app_id_list or 0) then
                        config_changed = true
                    else
                        local old_app_id_set = {}
                        if current_state.app_id_list then
                            for _, app_id in ipairs(current_state.app_id_list) do
                                old_app_id_set[app_id] = true
                            end
                        end
                        for _, app_id in ipairs(app_id_list) do
                            if not old_app_id_set[app_id] then
                                config_changed = true
                                break
                            end
                        end
                    end
                end

                if not config_changed then
                    if (tonumber(rule.filter_quic) or 0) ~= (tonumber(current_state.filter_quic) or 0) then
                        config_changed = true
                    end
                end
            end
            
            if not is_active or config_changed then
                if is_active then
                    log(string.format("AppFilter rule %d (%s): config changed, recreating", rule.id, rule.name))
                    delete_appfilter_rule(rule.id)
                else
                    log(string.format("AppFilter rule %d (%s): activating", rule.id, rule.name))
                end
                
                if create_appfilter_rule(rule.id) then
                    if not appfilter_rules_state[rule.id] then
                        appfilter_rules_state[rule.id] = {}
                    end

                    local mac_ok = set_appfilter_rule_mac_list(rule.id, mac_list)
                    local app_ok = mac_ok and set_appfilter_rule_app_id_list(rule.id, app_id_list)
                    local quic_ok = app_ok and (tonumber(rule.filter_quic) or 0) == 0
                    if mac_ok and app_ok and quic_ok then
                        appfilter_rules_state[rule.id].mac_list = mac_list
                        appfilter_rules_state[rule.id].app_id_list = app_id_list
                        appfilter_rules_state[rule.id].filter_quic = tonumber(rule.filter_quic) or 0
                        appfilter_rules_state[rule.id].active = true
                        appfilter_rules_state[rule.id].name = rule.name
                        appfilter_rules_state[rule.id].mode = rule.mode
                        appfilter_rules_state[rule.id].enabled = rule.enabled
                        log(string.format("AppFilter rule %d: activated successfully", rule.id))
                    else
                        delete_appfilter_rule(rule.id)
                        appfilter_rules_state[rule.id].active = false
                        log(string.format("ERROR: AppFilter rule %d configuration failed; partial kernel rule removed", rule.id))
                    end
                end
            else
                log(string.format("AppFilter rule %d: no changes needed", rule.id))
            end
        else
            if is_active then
                log(string.format("AppFilter rule %d (%s): deactivating (enabled=%d, time_match=%s)", 
                    rule.id, rule.name, rule.enabled, tostring(time_match)))
                if delete_appfilter_rule(rule.id) then
                    appfilter_rules_state[rule.id].active = false
                    log(string.format("AppFilter rule %d: deactivated", rule.id))
                end
            end
        end
    end
    
    for rule_id, state in pairs(appfilter_rules_state) do
        local found = false
        for _, rule in ipairs(rules) do
            if rule.id == rule_id then
                found = true
                break
            end
        end
        if not found then
            if state.active then
                log(string.format("AppFilter rule %d: removed from config.db, deleting", rule_id))
                if delete_appfilter_rule(rule_id) then
                    appfilter_rules_state[rule_id] = nil
                end
            else
                appfilter_rules_state[rule_id] = nil
            end
        end
    end
end

local function process_macfilter_rules(current_info)
    log(string.format("=== Processing MACFilter rules (time: %02d:%02d, weekday: %d) ===", 
        current_info.hour, current_info.min, current_info.weekday))
    
    local rules = load_macfilter_rules()
    
    local all_user_rules = {}  
    local single_user_rules = {}
    
    for _, rule in ipairs(rules) do
        if rule.enabled == 1 then
            local should_active = is_time_in_range(rule.time_rules, current_info)
            if should_active then
                if rule.mode == 1 then
                    table.insert(all_user_rules, rule)
                elseif rule.mode == 2 then
                    table.insert(single_user_rules, rule)
                end
            end
        end
    end
    
    log(string.format("MACFilter: Found %d all-user rules, %d single-user rules (active)", 
        #all_user_rules, #single_user_rules))
    
    for _, rule in ipairs(all_user_rules) do
        local current_state = macfilter_rules_state[rule.id]
        local is_active = current_state and current_state.active or false
        
        if not is_active then
            log(string.format("MACFilter rule %d (%s): activating (all-user mode, mac_list=empty)", 
                rule.id, rule.name))
            
            if create_macfilter_rule(rule.id) then
                if set_macfilter_rule_mac_list(rule.id, {}) then
                    if not macfilter_rules_state[rule.id] then
                        macfilter_rules_state[rule.id] = {}
                    end
                    macfilter_rules_state[rule.id].active = true
                    macfilter_rules_state[rule.id].mode = 1
                    macfilter_rules_state[rule.id].name = rule.name
                    log(string.format("MACFilter rule %d: activated successfully", rule.id))
                end
            end
        end
    end
    
    local mac_set = {}
    for _, rule in ipairs(single_user_rules) do
        if rule.enabled == 1 and rule.user_mac and rule.user_mac ~= "" then
            mac_set[rule.user_mac] = true
        end
    end
    
    local mac_list = {}
    for mac, _ in pairs(mac_set) do
        table.insert(mac_list, mac)
    end
    
    log(string.format("MACFilter: Merging %d single-user rules (enabled) into single MAC rule, total MACs: %d", 
        #single_user_rules, #mac_list))
    
    local single_mac_state = macfilter_rules_state[SINGLE_MAC_FILTER_RULE_ID]
    local single_mac_active = single_mac_state and single_mac_state.active or false
    
    local mac_list_changed = true
    if single_mac_state and single_mac_state.mac_list then
        local old_mac_set = {}
        for _, mac in ipairs(single_mac_state.mac_list) do
            old_mac_set[mac] = true
        end
        
        if #mac_list == #single_mac_state.mac_list then
            mac_list_changed = false
            for _, mac in ipairs(mac_list) do
                if not old_mac_set[mac] then
                    mac_list_changed = true
                    break
                end
            end
        end
    end
    
    local need_update = false
    if single_mac_active then
        need_update = mac_list_changed
    else
        need_update = (#mac_list > 0) or mac_list_changed
    end
    
    if need_update then
        log(string.format("MACFilter single-user rule: updating (active=%s, mac_list_changed=%s, mac_count=%d)", 
            tostring(single_mac_active), tostring(mac_list_changed), #mac_list))
        
        if set_macfilter_rule_mac_list(SINGLE_MAC_FILTER_RULE_ID, mac_list) then
            if not macfilter_rules_state[SINGLE_MAC_FILTER_RULE_ID] then
                macfilter_rules_state[SINGLE_MAC_FILTER_RULE_ID] = {}
            end
            macfilter_rules_state[SINGLE_MAC_FILTER_RULE_ID].active = (#mac_list > 0)
            macfilter_rules_state[SINGLE_MAC_FILTER_RULE_ID].mode = 2
            macfilter_rules_state[SINGLE_MAC_FILTER_RULE_ID].mac_list = mac_list
            macfilter_rules_state[SINGLE_MAC_FILTER_RULE_ID].name = "Time-based MAC Filter (Single User)"
            if #mac_list > 0 then
                log("MACFilter single-user rule: updated successfully")
            else
                log("MACFilter single-user rule: cleared (no enabled single-user rules)")
            end
        end
    else
        log(string.format("MACFilter single-user rule: no changes needed (active=%s, mac_list_changed=%s, mac_count=%d), skipping update", 
            tostring(single_mac_active), tostring(mac_list_changed), #mac_list))
    end
    
    for rule_id, state in pairs(macfilter_rules_state) do
        if rule_id ~= SINGLE_MAC_FILTER_RULE_ID and state.mode == 1 then
            local found = false
            for _, rule in ipairs(all_user_rules) do
                if rule.id == rule_id then
                    found = true
                    break
                end
            end
            if not found and state.active then
                log(string.format("MACFilter rule %d: no longer active (enable=0 or time mismatch), deleting", rule_id))
                if delete_macfilter_rule(rule_id) then
                    macfilter_rules_state[rule_id] = nil
                    log(string.format("MACFilter rule %d: deleted successfully", rule_id))
                else
                    log(string.format("MACFilter rule %d: delete failed", rule_id))
                end
            end
        end
    end
    
    for rule_id, state in pairs(macfilter_rules_state) do
        if rule_id ~= SINGLE_MAC_FILTER_RULE_ID then
            local found = false
            for _, rule in ipairs(rules) do
                if rule.id == rule_id then
                    found = true
                    break
                end
            end
            if not found then
                log(string.format("MACFilter rule %d: removed from config.db, cleaning up state", rule_id))
                macfilter_rules_state[rule_id] = nil
            end
        end
    end
end

local function apply_appfilter_enable(enable)
    log(string.format("=== Applying AppFilter enable: %d ===", enable))
    local proc_file = "/proc/sys/dreamingwrt/jmx/appfilter_enable"
    local file = io.open(proc_file, "w")
    if file then
        file:write(tostring(enable))
        file:close()
        log(string.format("AppFilter enable set to %d successfully", enable))
        return true
    else
        log(string.format("Failed to open %s for writing", proc_file))
        return false
    end
end

local function apply_macfilter_enable(enable)
    log(string.format("=== Applying MACFilter enable: %d ===", enable))
    local proc_file = "/proc/sys/dreamingwrt/jmx/macfilter_enable"
    local file = io.open(proc_file, "w")
    if file then
        file:write(tostring(enable))
        file:close()
        log(string.format("MACFilter enable set to %d successfully", enable))
        return true
    else
        log(string.format("Failed to open %s for writing", proc_file))
        return false
    end
end

local function check_and_apply_appfilter_enable()
    local current_enable = tonumber(rulesd_config and rulesd_config.appfilter_enabled) or 0
    if appfilter_enable_state == nil or appfilter_enable_state ~= current_enable then
        log(string.format("AppFilter enable changed: %s -> %d", 
            appfilter_enable_state == nil and "nil" or tostring(appfilter_enable_state), current_enable))
        if apply_appfilter_enable(current_enable) then
            appfilter_enable_state = current_enable
        end
    end
end

local function check_and_apply_macfilter_enable()
    local current_enable = tonumber(rulesd_config and rulesd_config.macfilter_enabled) or 0
    if macfilter_enable_state == nil or macfilter_enable_state ~= current_enable then
        log(string.format("MACFilter enable changed: %s -> %d", 
            macfilter_enable_state == nil and "nil" or tostring(macfilter_enable_state), current_enable))
        if apply_macfilter_enable(current_enable) then
            macfilter_enable_state = current_enable
        end
    end
end

local function apply_record_enable(enable)
    log(string.format("=== Applying Record enable: %d ===", enable))
    local proc_file = "/proc/sys/dreamingwrt/jmx/record_enable"
    local file = io.open(proc_file, "w")
    if file then
        file:write(tostring(enable))
        file:close()
        log(string.format("Record enable set to %d successfully", enable))
        return true
    else
        log(string.format("Failed to open %s for writing", proc_file))
        return false
    end
end

local function check_and_apply_record_enable()
    local current_enable = tonumber(rulesd_config and rulesd_config.record_enabled) or 0
    if record_enable_state == nil or record_enable_state ~= current_enable then
        log(string.format("Record enable changed: %s -> %d", 
            record_enable_state == nil and "nil" or tostring(record_enable_state), current_enable))
        if apply_record_enable(current_enable) then
            record_enable_state = current_enable
        end
    end
end

local function check_state_file(file_path)
    local file = io.open(file_path, "r")
    if not file then
        return false
    end
    
    local content = file:read("*line")
    file:close()
    
    return (content == "1")
end

local function reset_state_file(file_path)
    local file = io.open(file_path, "w")
    if file then
        file:write("0")
        file:close()
        return true
    end
    return false
end

local function check_reinit_flags()
    local appfilter_reinit = check_state_file(APPFILTER_STATE_FILE)
    local macfilter_reinit = check_state_file(MACFILTER_STATE_FILE)
    local appfilter_whitelist_reinit = check_state_file(APPFILTER_WHITELIST_STATE_FILE)
    local macfilter_whitelist_reinit = check_state_file(MACFILTER_WHITELIST_STATE_FILE)
    
    return appfilter_reinit, macfilter_reinit, appfilter_whitelist_reinit, macfilter_whitelist_reinit
end

local function flush_appfilter_rules()
    log("=== Flushing AppFilter rules ===")
    local json_str = '{"api":"flush_app_filter_rule","data":{}}'
    if write_to_dev_jmx(json_str) then
        log("AppFilter rules flushed successfully")
        return true
    else
        log("Failed to flush AppFilter rules")
        return false
    end
end

local function flush_macfilter_rules()
    log("=== Flushing MACFilter rules ===")
    local json_str = '{"api":"flush_mac_filter_rule","data":{}}'
    if write_to_dev_jmx(json_str) then
        log("MACFilter rules flushed successfully")
        return true
    else
        log("Failed to flush MACFilter rules")
        return false
    end
end

local function flush_appfilter_whitelist()
    log("=== Flushing AppFilter whitelist ===")
    local json_str = '{"api":"flush_app_filter_whitelist","data":{}}'
    if write_to_dev_jmx(json_str) then
        log("AppFilter whitelist flushed successfully")
        return true
    else
        log("Failed to flush AppFilter whitelist")
        return false
    end
end

local function flush_macfilter_whitelist()
    log("=== Flushing MACFilter whitelist ===")
    local json_str = '{"api":"flush_mac_filter_whitelist","data":{}}'
    if write_to_dev_jmx(json_str) then
        log("MACFilter whitelist flushed successfully")
        return true
    else
        log("Failed to flush MACFilter whitelist")
        return false
    end
end

local function load_appfilter_whitelist()
    local mac_list = rulesd_config and rulesd_config.app_whitelist or {}
    log(string.format("AppFilter whitelist: loaded %d MAC addresses from config.db", #mac_list))
    return mac_list
end

local function load_macfilter_whitelist()
    local mac_list = rulesd_config and rulesd_config.mac_whitelist or {}
    log(string.format("MACFilter whitelist: loaded %d MAC addresses from config.db", #mac_list))
    return mac_list
end

local function apply_appfilter_whitelist(mac_list)
    log(string.format("=== Applying AppFilter whitelist, count=%d ===", #mac_list))
    
    flush_appfilter_whitelist()
    
    if #mac_list > 0 then
        local mac_strs = {}
        for _, mac in ipairs(mac_list) do
            table.insert(mac_strs, string.format('"%s"', mac))
        end
        local mac_array_str = "[" .. table.concat(mac_strs, ",") .. "]"
        
        local json_str = string.format('{"api":"add_app_filter_whitelist","data":{"mac_list":%s}}', mac_array_str)
        if write_to_dev_jmx(json_str) then
            log(string.format("AppFilter whitelist applied successfully: %d MACs", #mac_list))
            return true
        else
            log("Failed to apply AppFilter whitelist")
            return false
        end
    else
        log("AppFilter whitelist is empty, no MACs to add")
        return true
    end
end

local function apply_macfilter_whitelist(mac_list)
    log(string.format("=== Applying MACFilter whitelist, count=%d ===", #mac_list))
    
    flush_macfilter_whitelist()
    
    if #mac_list > 0 then
        local mac_strs = {}
        for _, mac in ipairs(mac_list) do
            table.insert(mac_strs, string.format('"%s"', mac))
        end
        local mac_array_str = "[" .. table.concat(mac_strs, ",") .. "]"
        
        local json_str = string.format('{"api":"add_mac_filter_whitelist","data":{"mac_list":%s}}', mac_array_str)
        if write_to_dev_jmx(json_str) then
            log(string.format("MACFilter whitelist applied successfully: %d MACs", #mac_list))
            return true
        else
            log("Failed to apply MACFilter whitelist")
            return false
        end
    else
        log("MACFilter whitelist is empty, no MACs to add")
        return true
    end
end

local function whitelist_key(mac_list)
    return table.concat(mac_list or {}, "\n")
end

local function check_and_apply_whitelists(force)
    local app_list = load_appfilter_whitelist()
    local app_key = whitelist_key(app_list)
    if force or app_key ~= appfilter_whitelist_applied then
        if apply_appfilter_whitelist(app_list) then appfilter_whitelist_applied = app_key end
    end
    local mac_list = load_macfilter_whitelist()
    local mac_key = whitelist_key(mac_list)
    if force or mac_key ~= macfilter_whitelist_applied then
        if apply_macfilter_whitelist(mac_list) then macfilter_whitelist_applied = mac_key end
    end
end

local function interruptible_sleep(seconds)
    for i = 1, seconds do
        local result = os.execute("sleep 1")
        if result ~= 0 and result ~= true then
            return
        end
    end
end

local function flush_all_rules()
    log("=== Flushing all rules before initialization ===")
    
    local json_str = '{"api":"flush_mac_filter_rule","data":{}}'
    if write_to_dev_jmx(json_str) then
        log("MAC filter rules flushed")
    else
        log("Failed to flush MAC filter rules")
    end
    
    json_str = '{"api":"flush_app_filter_rule","data":{}}'
    if write_to_dev_jmx(json_str) then
        log("App filter rules flushed")
    else
        log("Failed to flush App filter rules")
    end
    
    json_str = '{"api":"flush_mac_filter_whitelist","data":{}}'
    if write_to_dev_jmx(json_str) then
        log("MAC filter whitelist flushed")
    else
        log("Failed to flush MAC filter whitelist")
    end
    
    json_str = '{"api":"flush_app_filter_whitelist","data":{}}'
    if write_to_dev_jmx(json_str) then
        log("App filter whitelist flushed")
    else
        log("Failed to flush App filter whitelist")
    end
    
    log("All rules flushed successfully")
    return true
end

local function initialize_rules()
    local loaded, err = refresh_rulesd_config()
    if not loaded then
        log("ERROR: config.db rules unavailable: " .. tostring(err))
        return false
    end
    flush_all_rules()
    check_and_apply_appfilter_enable()
    check_and_apply_macfilter_enable()
    check_and_apply_record_enable()  
    
    init_single_mac_rule()
    
    local appfilter_rules = load_appfilter_rules()
    for _, rule in ipairs(appfilter_rules) do
        appfilter_rules_state[rule.id] = {
            active = false,
            name = rule.name,
            mode = rule.mode,
            filter_quic = tonumber(rule.filter_quic) or 0
        }
    end
    
    local macfilter_rules = load_macfilter_rules()
    for _, rule in ipairs(macfilter_rules) do
        macfilter_rules_state[rule.id] = {
            active = false,
            mode = rule.mode,
            name = rule.name,
            user_mac = rule.user_mac
        }
    end
    
    log(string.format("Initialized: %d AppFilter rules, %d MACFilter rules", 
        #appfilter_rules, #macfilter_rules))
    
    log("=== Loading whitelists ===")
    check_and_apply_whitelists(true)
    log("Whitelists initialized successfully")
    return true
end

local function main_loop()
    log("Rule manager started")
    
    while not initialize_rules() do
        interruptible_sleep(CHECK_INTERVAL)
    end
    
    local running = true
    
    while running do
        local refreshed, refresh_err = refresh_rulesd_config()
        if not refreshed then
            log("ERROR: retaining last rules because config.db refresh failed: " .. tostring(refresh_err))
            interruptible_sleep(CHECK_INTERVAL)
        else
        check_and_apply_appfilter_enable()
        check_and_apply_macfilter_enable()
        check_and_apply_record_enable()
        check_and_apply_whitelists(false)
        local appfilter_reinit, macfilter_reinit, appfilter_whitelist_reinit, macfilter_whitelist_reinit = check_reinit_flags()
        
        if appfilter_whitelist_reinit then
            log("=== AppFilter whitelist state file detected change, reloading ===")
            check_and_apply_whitelists(true)
            if reset_state_file(APPFILTER_WHITELIST_STATE_FILE) then
                log("AppFilter whitelist state file reset to 0")
            else
                log("Failed to reset AppFilter whitelist state file")
            end
        end
        
        if macfilter_whitelist_reinit then
            log("=== MACFilter whitelist state file detected change, reloading ===")
            check_and_apply_whitelists(true)
            if reset_state_file(MACFILTER_WHITELIST_STATE_FILE) then
                log("MACFilter whitelist state file reset to 0")
            else
                log("Failed to reset MACFilter whitelist state file")
            end
        end
        
        if appfilter_reinit then
            log("=== AppFilter rules state file detected change, reinitializing ===")
            flush_appfilter_rules()
            
            check_and_apply_appfilter_enable()
            
            appfilter_rules_state = {}
            local appfilter_rules = load_appfilter_rules()
            for _, rule in ipairs(appfilter_rules) do
                appfilter_rules_state[rule.id] = {
                    active = false,
                    name = rule.name,
                    mode = rule.mode,
                    filter_quic = tonumber(rule.filter_quic) or 0
                }
            end
            log(string.format("AppFilter rules reinitialized: %d rules", #appfilter_rules))
            if reset_state_file(APPFILTER_STATE_FILE) then
                log("AppFilter state file reset to 0")
            else
                log("Failed to reset AppFilter state file")
            end
        end
        
        if macfilter_reinit then
            flush_macfilter_rules()
            
            check_and_apply_macfilter_enable()
            
            init_single_mac_rule()
            macfilter_rules_state = {}
            local macfilter_rules = load_macfilter_rules()
            for _, rule in ipairs(macfilter_rules) do
                macfilter_rules_state[rule.id] = {
                    active = false,
                    mode = rule.mode,
                    name = rule.name,
                    user_mac = rule.user_mac
                }
            end
            log(string.format("MACFilter rules reinitialized: %d rules", #macfilter_rules))
            if reset_state_file(MACFILTER_STATE_FILE) then
                log("MACFilter state file reset to 0")
            else
                log("Failed to reset MACFilter state file")
            end
        end
        
        local current_info = get_current_time_info()
        
        local ok, err = pcall(function()
            process_appfilter_rules(current_info)
            process_macfilter_rules(current_info)
        end)
        
        if not ok then
            log("ERROR processing rules: " .. tostring(err))
        end
        interruptible_sleep(CHECK_INTERVAL)
        end
    end
end

if arg[0] and (arg[0]:match("rule_manager") or arg[0]:match("dreamingwrt%-rulesd")) then
    main_loop()
end
