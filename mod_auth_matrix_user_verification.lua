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
-- Code referenced for async portion: https://hg.prosody.im/prosody-modules/file/39156d6f7268/mod_auth_http_async/mod_auth_http_async.lua
-- net.http documentation: https://prosody.im/doc/developers/net/http
-- util.async documentation: https://prosody.im/doc/developers/util/async

local async = require "util.async";
local formdecode = require "util.http".formdecode;
local generate_uuid = require "util.uuid".generate;
local jid = require "util.jid";
local jwt = module:require "luajwtjitsi";
local new_sasl = require "util.sasl".new;
local sasl = require "util.sasl";
local sessions = prosody.full_sessions;
local basexx = require "basexx";
local http = require "net.http";
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
    -- Set necessary HTTP headers for the request
    local options = {};
    options.headers = {};
    options.headers["Content-Type"] = "application/json";
    if uvsAuthToken ~= nil then
        module:log("debug", "Setting authentication header with Bearer token");
        options.headers["Authorization"] = string.format("Bearer %s", uvsAuthToken)
    end

    -- Set the body of the request with details provided by the client
    module:log("info", "Found room ID: %s, server_name: %s", matrix.room_id, matrix.server_name);
    if matrix.server_name ~= nil then
        options.body = json.encode({ token = matrix.token, room_id = matrix.room_id, matrix_server_name = matrix.server_name });
    else
        options.body = json.encode({ token = matrix.token, room_id = matrix.room_id });
    end

    -- We want to make this HTTP call in an asynchronous manner
    -- wait and done allow us to pause execution of the function while we wait for a long-running operation,
    -- such as contacting the User Verification Service, to complete.
    -- We pause the function with wait, then call done() when the request is complete to unpause where we left off
    local wait, done = async.waiter();
    local data;

    local function cb(response_body, response_code, request, response)
        module:log("debug", "Response code: %d", response_code);
        module:log("debug", "Response body: %s", response_body);

        if response_code == 200 then
            -- Deserialise the body
            data = json.decode(response_body);
        end

        done();
    end

    -- Make the request and pause execution of this function until done is called above
    -- Note the request will automatically have a method of POST if a body is included
    http.request(string.format("%s/verify/user_in_room", uvsUrl), options, cb);
    wait();

    if data == nil or not data.results then
        module:log("info", "REQUEST_COMPLETE reason:invalid_response")
        return false, false;
    end

    if data.results.user == true and data.results.room_membership == true then
        if uvsSyncPowerLevels and data.power_levels ~= nil then
            -- If the user power in the room is at least "state_default", we mark them as owner
            if data.power_levels.user >= data.power_levels.room.state_default then
                return true, true;
            end
        end

        -- The user is in the room, but they're not considered a moderator
        return true, false;
    else
        if data.results.user == true and data.results.room_membership == false then
            module:log("info", "REQUEST_COMPLETE reason:not_in_room")
        else
            module:log("info", "REQUEST_COMPLETE reason:invalid_token")
        end
    end

    return false, false;
end

local function process_and_verify_token(session)
    if session.auth_token == nil then
        module:log("info", "REQUEST_COMPLETE reason:invalid_auth_token")
        return false, "bad-request", "JWT token must be provided with OpenID token and room ID";
    end
    if jwt.decode == nil then
        data, msg = jwt.verify(session.auth_token, "HS256", "notused");
    else
	data, msg = jwt.decode(session.auth_token);
    end
    if data == nil then
        module:log("info", "REQUEST_COMPLETE reason:auth_token_decode_issue")
        return false, "bad-request", "JWT token cannot be decoded";
    end

    if not data.context.matrix or data.context.matrix.room_id == nil then
        module:log("info", "REQUEST_COMPLETE reason:missing_matrix_room_id")
        return false, "bad-request", "Matrix room ID must be given."
    end

    local decodedRoomId = basexx.from_base32(session.jitsi_room);
    if decodedRoomId ~= data.context.matrix.room_id then
        module:log("info", "REQUEST_COMPLETE reason:jitsi_and_matrix_room_mismatch")
        return false, "access-denied", "Jitsi room does not match Matrix room"
    end

    local isMember, isOwner = verify_room_membership(data.context.matrix);

    if isMember ~= true then
        return false, "access-denied", "Token invalid or not in room";
    end

    if isOwner ~= true then
        isOwner = false
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
            module:log("warn",
                "Error verifying membership err:%s, reason:%s", error, reason);
            session.auth_token = nil;
            return res, error, reason;
        end

        local customUsername
            = prosody.events.fire_event("pre-jitsi-authentication", session);

        module:log("warn", "Custom username: %s", customUsername);

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
        module:log("warn", "self.username: %s", self.username);

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
		module:log("info", "REQUEST_COMPLETE reason:ok")
		return "success";
	else
		return "failure", err, msg;
	end
end

sasl.registerMechanism("ANONYMOUS", {"anonymous"}, anonymous);
