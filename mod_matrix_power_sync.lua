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

local jid_bare = require "util.jid".bare;
local um_is_admin = require "core.usermanager".is_admin;

-- Source: https://github.com/jitsi/jitsi-meet/blob/master/resources/prosody-plugins/util.lib.lua#L248
local function starts_with(str, start)
    return str:sub(1, #start) == start
end

-- healthcheck rooms in jicofo starts with a string '__jicofo-health-check'
-- Source: https://github.com/jitsi/jitsi-meet/blob/master/resources/prosody-plugins/util.lib.lua#L253
local function is_healthcheck_room(room_jid)
    if starts_with(room_jid, "__jicofo-health-check") then
        return true;
    end

    return false;
end

local function is_admin(jid)
    return um_is_admin(jid, module.host);
end

-- Adapted from https://github.com/nvonahsen/jitsi-token-moderation-plugin/blob/a5ebdfaa38a6adde6bceba62cfbc5b1693e480b9/mod_token_moderation.lua
function setupAffiliation(room, origin, stanza)
    local jid = jid_bare(stanza.attr.from);
    if origin.auth_matrix_user_verification_is_owner == true or is_admin(jid) then
        module:log("info", "Setting %s as owner of room %s based on Matrix power levels", jid, room.jid);
        room:set_affiliation("matrix_power_sync", jid, "owner");
    else
        room:set_affiliation("matrix_power_sync", jid, "member");
    end;
end;

-- Hook into room creation to add this wrapper to every new room
-- Adapted from https://github.com/nvonahsen/jitsi-token-moderation-plugin/blob/a5ebdfaa38a6adde6bceba62cfbc5b1693e480b9/mod_token_moderation.lua
--
-- Adds hooks to room creation to:
-- 1) Allow setting owner of room only via this plugin (stops Jitsi auto-ownering when owners drop out)
-- 2) Set owner for anyone based on the session.auth_matrix_user_verification_is_owner value, which is set
--    when the user authenticates. Should it not exist, the user is a normal member.
module:hook("muc-room-created", function(event)
    if is_healthcheck_room(event.room.jid) then
        module:log("debug", "Skipping adding power sync hooks, this is a healthcheck room");
        return;
    end;

    module:log('info', 'Room created, adding mod_matrix_power_sync module code');
    local room = event.room;
    local _handle_normal_presence = room.handle_normal_presence;
    local _handle_first_presence = room.handle_first_presence;
    -- Wrap presence handlers to set affiliations from our way whenever a user joins
    room.handle_normal_presence = function(thisRoom, origin, stanza)
        local pres = _handle_normal_presence(thisRoom, origin, stanza);
        setupAffiliation(thisRoom, origin, stanza);
        return pres;
    end;
    room.handle_first_presence = function(thisRoom, origin, stanza)
        local pres = _handle_first_presence(thisRoom, origin, stanza);
        setupAffiliation(thisRoom, origin, stanza);
        return pres;
    end;
    -- Wrap set affilaition to block anything but token setting owner (stop pesky auto-ownering)
    local _set_affiliation = room.set_affiliation;
    room.set_affiliation = function(room, actor, jid, affiliation, reason)
        module:log(
            "debug",
            "room.set_affiliation: room:%s, actor:%s, jid:%s, affiliation:%s, reason:%s",
            room.jid, actor, jid, affiliation, reason
        );
        -- let this plugin do whatever it wants
        if actor == "matrix_power_sync" then
            return _set_affiliation(room, true, jid, affiliation, reason)
        -- noone else can assign owner (in order to block prosody/jitsi's built in moderation functionality
        elseif affiliation == "owner" then
            return nil, "modify", "not-acceptable"
        -- keep other affil stuff working as normal (hopefully, haven't needed to use/test any of it)
        else
            return _set_affiliation(room, actor, jid, affiliation, reason);
        end;
    end;
end);
