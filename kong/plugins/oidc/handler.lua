local BasePlugin = require "kong.plugins.base_plugin"
local OidcHandler = BasePlugin:extend()
local utils = require("kong.plugins.oidc.utils")
local filter = require("kong.plugins.oidc.filter")
local session = require("kong.plugins.oidc.session")
local cjson = require("cjson")
local openidc = require("resty.openidc")
local constants = require("kong.plugins.oidc.util.constants")

OidcHandler.PRIORITY = 1000

function OidcHandler:new()
  OidcHandler.super.new(self, "oidc")
end

function OidcHandler:access(config)
  OidcHandler.super.access(self)
  local oidcConfig, oidcSessionConfig = utils.get_options(config, ngx)

  if filter.shouldProcessRequest(oidcConfig) then
    ngx.log(ngx.DEBUG, "OidcHandler processing request, path: " .. ngx.var.request_uri)
    session.configure(config)
    handle(oidcConfig, oidcSessionConfig)
  else
    ngx.log(ngx.DEBUG, "OidcHandler ignoring request, path: " .. ngx.var.request_uri)
  end

  ngx.log(ngx.DEBUG, "OidcHandler done")
end

function handle(oidcConfig, oidcSessionConfig)
  local response

  -- clear oidc plugin headers to prevent spoofing of info to upstream api
  utils.clear_request_headers()

  -- get/cache discovery data, mutate oidcConfig.discovery if it is a string (discovery endpoint)
  openidc.get_discovery_doc(oidcConfig)

  -- attempt introspection of potential bearer token
  if oidcConfig.discovery.introspection_endpoint then
    response = introspect(oidcConfig)
    -- if response, then introspect successful
    if response then
      local access_token = utils.get_bearer_access_token_from_header(oidcConfig)
      local userinfo, err = get_userinfo(oidcConfig, access_token, response.id_token)

      -- @todo: how can we distinguish between access_token and id_token?
      -- @see: https://developer.okta.com/docs/reference/api/oidc/#introspect
      -- err can occur due to id_token being used for authorization header instead of access_token
      if err or not userinfo then
        ngx.log(ngx.DEBUG, "call to userinfo endpoint failed, attaching decoded token to user")
        -- introspect passed but userinfo failed, set userinfo to decoded token instead of leaving blank
        userinfo = response
      end

      response = {
        access_token = access_token,
        user = userinfo
      }

    end
  end

  -- no valid access token, force oidc authentication
  if response == nil then
    response = make_oidc(oidcConfig, oidcSessionConfig)

    -- @todo: prevent 2nd call during authorization code flow
    if response and response.access_token then
      response.user = get_userinfo(oidcConfig, response.access_token, response.id_token)
    end
  end

  -- attach headers if we have them
  if response then
    if (response.user) then
      utils.injectUser(response.user)
    end
    if (response.access_token) then
      utils.injectAccessToken(response.access_token)
    end
    if (response.id_token) then
      utils.injectIDToken(response.id_token)
    end
  end
end

function make_oidc(oidcConfig, oidcSessionConfig)
  ngx.log(ngx.DEBUG, "OidcHandler calling authenticate, requested path: " .. ngx.var.request_uri)

  -- inspiration: https://docs.konghq.com/hub/kong-inc/openid-connect/, see authorization_query_args_client
  -- check request args for login_hint and if exists then add
  local args, err = ngx.req.get_uri_args()
  if args then
    local login_hint = args["login_hint"]
    if login_hint then
      ngx.log(ngx.DEBUG, "OidcHandler login_hint found: " .. login_hint .. ", adding it to authorization_params")
      oidcConfig["authorization_params"] = {
        login_hint = login_hint
      }
    end
  end

  local ngx_headers = ngx.req.get_headers()
  local isAjaxRequest = ngx_headers and ngx_headers["X-Requested-With"] == "XMLHttpRequest"

  -- default value for unauth_action is based on force_authentication_path being set.
  -- If set, unauth_action is set to "pass", default action is to allow request through to the upstream service.
  -- If not set, unauth_action is set to nil, default action is to redirect request to idp authentication.
  local unauth_action = oidcConfig.force_authentication_path and constants.UNAUTH_ACTION.PASS or constants.UNAUTH_ACTION.NIL

  -- if uri requested matches force authentication path, then user must be authenticated to hit upstream api (set unauth_action to nil)
  if ngx.var.uri == oidcConfig.force_authentication_path then
    ngx.log(ngx.DEBUG, "OidcHandler force_authentication_path matched request, setting unauth_action = nil")
    unauth_action = constants.UNAUTH_ACTION.NIL
  end

  local isGoingToRedirectIfUnauthenticated = unauth_action == constants.UNAUTH_ACTION.NIL
  -- if request is an ajax request and we are forcing authentication, set unauth_action to deny, preventing 302 Http response (redirect)
  if isAjaxRequest and isGoingToRedirectIfUnauthenticated then
    -- reference: https://github.com/zmartzone/lua-resty-openidc/blob/master/lib/resty/openidc.lua#L1436
    ngx.log(ngx.DEBUG, "OidcHandler ajax/async request detected, setting unauth_action = deny")
    -- set unauth_action to deny, which will prevent openidc.authenticate from redirecting if user is unauthenticated
    unauth_action = constants.UNAUTH_ACTION.DENY
  end

  local res, err, original_url, session = openidc.authenticate(oidcConfig, nil, unauth_action, oidcSessionConfig)

  -- @todo: add unit test to check for session:close()
  -- handle and close session, prevent locking
  session:close()

  -- if err is "unauthorized request" we know that token/session has expired/invalid AND request is Ajax/Async since
  -- code execution has gone this far, so return 401 status code to allow client to respond accordingly
  if err == "unauthorized request" then
    ngx.log(ngx.DEBUG, "OidcHandler unauthorized ajax/async request detected, responding with 401 status code")
    local message = cjson.encode({ status = ngx.HTTP_UNAUTHORIZED, request_path = ngx.var.request_uri})
    return utils.exit(ngx.HTTP_UNAUTHORIZED, message, ngx.HTTP_UNAUTHORIZED)
  end

  if err then
    if oidcConfig.recovery_page_path then
      ngx.log(ngx.DEBUG, "Entering recovery page: " .. oidcConfig.recovery_page_path)
      ngx.redirect(oidcConfig.recovery_page_path)
    end
    utils.exit(500, err, ngx.HTTP_INTERNAL_SERVER_ERROR)
  end
  return res
end

function introspect(oidcConfig)
  if utils.has_bearer_access_token() or oidcConfig.bearer_only == "yes" then
    -- introspect token
    local res, err = openidc.introspect(oidcConfig)

    -- check if token is valid (err returned)
    if err then
      if oidcConfig.bearer_only == "yes" then
        ngx.header["WWW-Authenticate"] = 'Bearer realm="' .. oidcConfig.realm .. '",error="' .. err .. '"'
        utils.exit(ngx.HTTP_UNAUTHORIZED, err, ngx.HTTP_UNAUTHORIZED)
      end
      return nil
    end
    ngx.log(ngx.DEBUG, "OidcHandler introspect succeeded, requested path: " .. ngx.var.request_uri)
    return res
  end
  return nil
end

function get_userinfo(oidcConfig, access_token, id_token)
  -- todo: should we use session instead?
  -- todo: add tests to verify cache hit
  local userinfo = utils.cache_get("userinfo", access_token)
  local err = nil

  -- cache hit
  if userinfo then
    userinfo = cjson.decode(userinfo)

    -- check if decoded value is blank
    if userinfo == cjson.null then
      ngx.log(ngx.DEBUG, "userinfo cached value is null returning nil value")
      return nil
    end

    return userinfo
  end

  ngx.log(ngx.INFO, "userinfo cache miss, calling userinfo endpoint")
  userinfo, err = openidc.call_userinfo_endpoint(oidcConfig, access_token)

  if err then
    ngx.log(ngx.ERR, "call to userinfo endpoint failed, ", err)
    return nil, err
  end

  -- @see openidc.introspect https://github.com/zmartzone/lua-resty-openidc/blob/master/lib/resty/openidc.lua#L1575
  -- utilized openidc.introspect caching logic
  -- todo: add tests to verify values are respected
  local introspection_cache_ignore = oidcConfig.introspection_cache_ignore or false
  local expiry_claim = oidcConfig.introspection_expiry_claim or "exp"
  local introspection_interval = oidcConfig.introspection_interval or oidcConfig.userinfo_interval or 0

  -- NOTE: id_token is what is used in lua-resty-openidc to determine expiration NOT access token
  if not introspection_cache_ignore and id_token and id_token[expiry_claim] then
    local ttl = id_token[expiry_claim]

    if expiry_claim == "exp" then --https://tools.ietf.org/html/rfc7662#section-2.2
      ttl = ttl - ngx.time()
    end
    if introspection_interval > 0 then
      if ttl > introspection_interval then
        ttl = introspection_interval
      end
    end
    ngx.log(ngx.DEBUG, "setting cache now")
    ngx.log(ngx.DEBUG, "cache ttl: " .. ttl)
    -- add issued at time for upstream services to be aware of when this has changed
    userinfo.iat = ngx.time()
    utils.cache_set("userinfo", access_token, cjson.encode(userinfo), ttl)
  end

  return userinfo
end


return OidcHandler
