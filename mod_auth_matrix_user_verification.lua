-- Matrix room membership authentication
-- Copyright (C) 2020 New Vector
--
-- Based on https://github.com/jitsi/jitsi-meet/blob/b765adca752c5bda95b15791e8421852c8ab7000/resources/prosody-plugins/mod_auth_token.lua

local async = require "util.async";
local base64 = require "util.encodings".base64;
local formdecode = require "util.http".formdecode;
local generate_uuid = require "util.uuid".generate;
local http = require "net.http";
local jwt = require "luajwtjitsi";
local new_sasl = require "util.sasl".new;
local sasl = require "util.sasl";
local sessions = prosody.full_sessions;

-- Ensure configured
local uvsUrl = module:get_option("uvs_base_url", nil);
if uvsUrl == nil then
    module:log("warn", "Missing 'uvs_base_url' config, not configuring matrix_room_membership auth");
    return;
else
    module:log("info", string.format("uvs_base_url = %s", uvsUrl));
end

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

local function verify_room_membership(matrix)
    local wait, done = async.waiter();
    local result;
    local function cb(response_body, response_code, response)
        if response_code == 200 then
            local data = json.decode(response_body);
            if data.results and data.results.user == true and data.results.room_membership == true then
                result = true;
                done();
                return;
            end
        end
        result = false;
        done();
    end

    local options = {};
    options.headers = {};
    options.headers["Content-Type"] = "application/json";
    options.body = { token = matrix.token, room_id = matrix.room_id };
    http.request(string.format("%s/verify/user_in_room", uvsUrl), options, cb);
    wait();
    return result;
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

    if base64.decode(session.jitsi_room) ~= data.context.matrix.room_id then
        return false, "access-denied", "Jitsi room does not match Matrix room"
    end

    local result = verify_room_membership(data.context.matrix)

    if result == false then
    return false, "access-denied", "Token invalid or not in room";
    end

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
