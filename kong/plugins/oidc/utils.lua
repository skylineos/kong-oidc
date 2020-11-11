local cjson = require("cjson")
local constants = require("kong.plugins.oidc.util.constants")

local M = {}

local function parseFilters(csvFilters)
  local filters = {}
  if (not (csvFilters == nil)) then
    for pattern in string.gmatch(csvFilters, "[^,]+") do
      table.insert(filters, pattern)
    end
  end
  return filters
end

function M.get_options(config, ngx)

  -- check to see if override is provided
  local discovery = config.discovery
  if config.discovery_override then
    discovery = config.discovery_override
  end

  -- return TWO separate values as we don't want to pollute opts.session
  return {
    client_id = config.client_id,
    client_secret = config.client_secret,
    discovery = discovery,
    timeout = config.timeout,
    introspection_endpoint_auth_method = config.introspection_endpoint_auth_method,
    introspection_expiry_claim = config.introspection_expiry_claim,
    introspection_cache_ignore = config.introspection_cache_ignore,
    introspection_interval = config.introspection_interval,
    refresh_session_interval = config.refresh_session_interval,
    bearer_only = config.bearer_only,
    realm = config.realm,
    redirect_uri = config.redirect_uri,
    scope = config.scope,
    prompt = config.prompt,
    response_type = config.response_type,
    ssl_verify = config.ssl_verify,
    token_endpoint_auth_method = config.token_endpoint_auth_method,
    recovery_page_path = config.recovery_page_path,
    filters = parseFilters(config.filters),
    logout_path = config.logout_path,
    redirect_after_logout_uri = config.redirect_after_logout_uri,
    force_authentication_path = config.force_authentication_path
  }, config.session
end

function M.exit(httpStatusCode, message, ngxCode)
  ngx.status = httpStatusCode
  ngx.say(message)
  ngx.exit(ngxCode)
end

function M.injectAccessToken(accessToken)
  ngx.req.set_header(constants.REQUEST_HEADERS.X_ACCESS_TOKEN, accessToken)
end

function M.injectIDToken(idToken)
  local tokenStr = cjson.encode(idToken)
  ngx.req.set_header(constants.REQUEST_HEADERS.X_ID_TOKEN, ngx.encode_base64(tokenStr))
end

function M.injectUser(user)
  local tmp_user = user
  tmp_user.id = user.sub
  tmp_user.username = user.preferred_username
  ngx.ctx.authenticated_credential = tmp_user
  local userinfo = cjson.encode(user)
  ngx.req.set_header(constants.REQUEST_HEADERS.X_USERINFO, ngx.encode_base64(userinfo))
end

function M.has_bearer_access_token()
  local header = ngx.req.get_headers()['Authorization']
  if header and header:find(" ") then
    local divider = header:find(' ')
    if string.lower(header:sub(0, divider-1)) == string.lower("Bearer") then
      return true
    end
  end
  return false
end

function M.get_bearer_access_token_from_header(opts)

  local err

  -- get the access token from the Authorization header
  local headers = ngx.req.get_headers()
  local header_name = "Authorization"
  local header = headers[header_name]

  if header == nil or header:find(" ") == nil then
    err = "no Authorization header found"
    ngx.log(ngx.ERR, err)
    return nil, err
  end

  local divider = header:find(' ')
  if string.lower(header:sub(0, divider - 1)) ~= string.lower("Bearer") then
    err = "no Bearer authorization header value found"
    ngx.log(ngx.ERR, err)
    return nil, err
  end

  local access_token = header:sub(divider + 1)
  if access_token == nil then
    err = "no Bearer access token value found"
    ngx.log(ngx.ERR, err)
    return nil, err
  end

  return access_token, err
end

-- @see openidc_cache_set https://github.com/zmartzone/lua-resty-openidc/blob/master/lib/resty/openidc.lua#L101
function M.cache_set(type, key, value, exp)
  local dict = ngx.shared[type]
  if dict and (exp > 0) then
    local success, err, forcible = dict:set(key, value, exp)
    ngx.log(ngx.DEBUG, "cache set: success=", success, " err=", err, " forcible=", forcible)
  end
end

-- @see openidc_cache_get https://github.com/zmartzone/lua-resty-openidc/blob/master/lib/resty/openidc.lua#L110
function M.cache_get(type, key)
  local dict = ngx.shared[type]
  local value
  if dict then
    value = dict:get(key)
    if value then ngx.log(ngx.DEBUG, "cache hit: type=" .. type .. " key=" .. key) end
  end
  return value
end

function M.clear_request_headers()
  ngx.req.clear_header(constants.REQUEST_HEADERS.X_ACCESS_TOKEN)
  ngx.req.clear_header(constants.REQUEST_HEADERS.X_ID_TOKEN)
  ngx.req.clear_header(constants.REQUEST_HEADERS.X_USERINFO)
end

return M
