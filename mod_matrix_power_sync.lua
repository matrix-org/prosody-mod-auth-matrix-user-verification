-- Copyright 2021 The Matrix.org Foundation C.I.C.
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

local jid = require "util.jid";
local um_is_admin = require "core.usermanager".is_admin;

-- Source: https://github.com/jitsi/jitsi-meet/blob/master/resources/prosody-plugins/util.lib.lua#L248
local function starts_with(str, start)
    return str:sub(1, #start) == start
end

--- Extracts the subdomain and room name from internal jid node [foo]room1
-- @return subdomain(optional, if extracted or nil), the room name
-- Source: https://github.com/jitsi/jitsi-meet/blob/master/resources/prosody-plugins/util.lib.lua#L239
local function extract_subdomain(room_node)
    -- optimization, skip matching if there is no subdomain, no [subdomain] part in the beginning of the node
    if not starts_with(room_node, '[') then
        return nil, room_node;
    end

    return room_node:match("^%[([^%]]+)%](.+)$");
end

-- healthcheck rooms in jicofo starts with a string '__jicofo-health-check'
-- Source: https://github.com/jitsi/jitsi-meet/blob/master/resources/prosody-plugins/util.lib.lua#L253
local function is_healthcheck_room(room_jid)
    if starts_with(room_jid, "__jicofo-health-check") then
        return true;
    end

    return false;
end

-- Mostly taken from https://github.com/jitsi/jitsi-meet/blob/master/resources/prosody-plugins/mod_muc_allowners.lua#L63
local function should_sync_power_level(room, occupant, session)
    if is_healthcheck_room(room.jid) or um_is_admin(occupant.jid, module.host) then
        module:log("debug", "should_sync_power_level: no, this is a healthcheck room or occupant is already admin");
        return false;
    end

    local room_node = jid.node(room.jid);
    -- parses bare room address, for multidomain expected format is:
    -- [subdomain]roomName@conference.domain
    local target_subdomain, target_room_name = extract_subdomain(room_node);

    if not (target_room_name == session.jitsi_room) then
        module:log(
            "debug",
            "should_sync_power_level: no, room name %s does not match jitsi room name %s",
            target_room_name,
            session.jitsi_room
        );
        return false;
    end

    if not (target_subdomain == session.jitsi_meet_context_group) then
        module:log(
            "debug",
            "should_sync_power_level: no, room subdomain does not match jitsi context group",
            target_subdomain,
            session.jitsi_meet_context_group
        );
        return false;
    end

    return true;
end

module:hook("muc-occupant-joined", function (event)
    module:log(
        "debug",
        "muc-occupant-joined: room:%s, occupant:%s, auth_matrix_user_verification_is_owner:%s",
        event.room.jid,
        event.occupant.jid,
        event.origin.auth_matrix_user_verification_is_owner
    );

    local room = event.room;
    local occupant = event.occupant;
    local session = event.origin;

    -- Check if we want to sync power level for this room
    if not should_sync_power_level(room, occupant, session) then
        return;
    end

    if session.auth_matrix_user_verification_is_owner ~= true then
        return;
    end

    module:log("info", "Setting %s as owner of room %s based on Matrix power levels", occupant.jid, room.jid);

    -- Otherwise, set user owner
    room:set_affiliation(true, occupant.bare_jid, "owner");
end, 2);
