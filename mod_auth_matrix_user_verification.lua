-- Copyright 2020, 2021 The Matrix.org Foundation C.I.C.
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
--
-- Based on https://github.com/jitsi/jitsi-meet/blob/b765adca752c5bda95b15791e8421852c8ab7000/resources/prosody-plugins/mod_auth_token.lua

local formdecode = require "util.http".formdecode;
local generate_uuid = require "util.uuid".generate;
local jid = require "util.jid";
local jwt = require "luajwtjitsi";
local new_sasl = require "util.sasl".new;
local sasl = require "util.sasl";
local sessions = prosody.full_sessions;
local basexx = require "basexx";
local http_request = require "http.request";
local json = require "util.json";

-- Ensure configured
local uvsUrl = module:get_option("uvs_base_url", nil);
if uvsUrl == nil then
    module:log("warn", "Missing 'uvs_base_url' config, not configuring matrix_room_membership auth");
    return;
else
    module:log("info", string.format("uvs_base_url = %s", uvsUrl));
end
local uvsAuthToken = module:get_option("uvs_auth_token", nil);
if uvsAuthToken == nil then
    module:log("info", "No uvs_auth_token supplied, not sending authentication headers");
else
    module:log("info", "uvs_auth_token is set");
end

local uvsSyncPowerLevels = module:get_option("uvs_sync_power_levels", false);
module:log("info", "uvsSyncPowerLevels = %s", uvsSyncPowerLevels);

-- define auth provider
local provider = {};

local host = module.host;

-- Extract 'token' param from URL when session is created
function init_session(event)
	local session, request = event.session, event.request;
	local query = request.url.query;

	if query ~= nil then
        local params = formdecode(query);

        -- token containing the information we need: openid token and room ID
        session.auth_token = query and params.token or nil;

        -- previd is used together with https://modules.prosody.im/mod_smacks.html
        -- the param is used to find resumed session and re-use anonymous(random) user id
        -- (see get_username_from_token)
        session.previd = query and params.previd or nil;

        -- The room name
        session.jitsi_room = params.room;
    end
end

module:hook_global("bosh-session", init_session);
module:hook_global("websocket-session", init_session);

function provider.test_password(username, password)
	return nil, "Password based auth not supported";
end

function provider.get_password(username)
	return nil;
end

function provider.set_password(username, password)
	return nil, "Set password not supported";
end

function provider.user_exists(username)
	return nil;
end

function provider.create_user(username, password)
	return nil;
end

function provider.delete_user(username)
	return nil;
end

-- Check room membership from UVS
-- Returns boolean(isMember), boolean(isOwner)
local function verify_room_membership(matrix)
    local request = http_request.new_from_uri(string.format("%s/verify/user_in_room", uvsUrl));
    request.headers:upsert(":method", "POST");
    request.headers:upsert("content-type", "application/json");
    if uvsAuthToken ~= nil then
        module:log("debug", "Setting authentication header with Bearer token");
        request.headers:upsert(
            "authorization",
            string.format("Bearer %s", uvsAuthToken)
        )
    end
    module:log("info", "Found matrix %s %s", matrix.room_id, matrix.server_name);
    if matrix.server_name ~= nil then
        request:set_body(string.format(
            '{"token": "%s", "room_id": "%s", "matrix_server_name": "%s"}',
            matrix.token, matrix.room_id, matrix.server_name
        ));
    else
        request:set_body(string.format('{"token": "%s", "room_id": "%s"}', matrix.token, matrix.room_id));
    end
    local headers, stream = assert(request:go());
    local body = assert(stream:get_body_as_string());
    local status = headers:get(":status");
    if status == "200" then
        local data = json.decode(body);
        if data.results and data.results.user == true and data.results.room_membership == true then
            if uvsSyncPowerLevels and data.power_levels ~= nil then
                -- If the user power in the room is at least "state_detault", we mark them as owner
                if data.power_levels.user >= data.power_levels.room.state_default then
                    return true, true;
                end
            end
            return true, false;
        end
    end
    return false, false;
end

local function process_and_verify_token(session)
    if session.auth_token == nil then
        return false, "bad-request", "JWT token must be provided with OpenID token and room ID";
    end
    local data, msg = jwt.decode(session.auth_token);
    if data == nil then
        return false, "bad-request", "JWT token cannot be decoded";
    end

    if not data.context.matrix or data.context.matrix.room_id == nil then
        return false, "bad-request", "Matrix room ID must be given."
    end

    local decodedRoomId = basexx.from_base32(session.jitsi_room);
    if decodedRoomId ~= data.context.matrix.room_id then
        return false, "access-denied", "Jitsi room does not match Matrix room"
    end

    local isMember, isOwner = verify_room_membership(data.context.matrix)

    if isMember == false then
        return false, "access-denied", "Token invalid or not in room";
    end

    -- Store the isOwner detail
    session.auth_matrix_user_verification_is_owner = isOwner
    -- Store some data in the session from the token
    session.jitsi_meet_context_user = data.context.user;
    session.jitsi_meet_context_features = data.context.features;
    session.jitsi_meet_context_group = data.context.group;
    return true;
    end

function provider.get_sasl_handler(session)

	local function get_username_from_token(self, message)
        local res, error, reason = process_and_verify_token(session);

        if (res == false) then
            log("warn",
                "Error verifying membership err:%s, reason:%s", error, reason);
            session.auth_token = nil;
            return res, error, reason;
        end

        local customUsername
            = prosody.events.fire_event("pre-jitsi-authentication", session);

        log("warn", "Custom username: %s", customUsername);

        if (customUsername) then
            self.username = customUsername;
        elseif (session.previd ~= nil) then
            for _, session1 in pairs(sessions) do
                if (session1.resumption_token == session.previd) then
                    self.username = session1.username;
                    break;
                end
        	end
        else
            self.username = message;
        end
        log("warn", "self.username: %s", self.username);

        return res;
	end

	return new_sasl(host, { anonymous = get_username_from_token });
end

module:provides("auth", provider);

local function anonymous(self, message)

	local username = generate_uuid();

	-- This calls the handler created in 'provider.get_sasl_handler(session)'
	local result, err, msg = self.profile.anonymous(self, username, self.realm);

	if result == true then
		if (self.username == nil) then
			self.username = username;
		end
		return "success";
	else
		return "failure", err, msg;
	end
end

sasl.registerMechanism("ANONYMOUS", {"anonymous"}, anonymous);
