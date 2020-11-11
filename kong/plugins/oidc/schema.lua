local typedefs = require "kong.db.schema.typedefs"

return {
  name = "kong-oidc",
  fields = {
    { consumer = typedefs.no_consumer },
    {
      config = {
        type = "record",
        fields = {
          { client_id = { type = "string", required = true } },
          { client_secret = { type = "string", required = true } },
          -- @todo: should discovery be required, since we allow override?
          { discovery = { type = "string", required = true, default = "https://.well-known/openid-configuration" } },
          { introspection_endpoint_auth_method = { type = "string", required = false } },
          { introspection_expiry_claim = { type = "string", required = false } },
          { introspection_cache_ignore = { type = "boolean", required = false } },
          { introspection_interval = { type = "number", required = false } },
          { refresh_session_interval = { type = "number", required = false }},
          { timeout = { type = "number", required = false } },
          { bearer_only = { type = "string", required = true, default = "no" } },
          { realm = { type = "string", required = true, default = "kong" } },
          { redirect_uri = { type = "string" } },
          { redirect_uri_path = { type = "string"} },
          { scope = { type = "string", required = true, default = "openid" } },
          { prompt = { type = "string", required = false } },
          { response_type = { type = "string", required = true, default = "code" } },
          { ssl_verify = { type = "string", required = true, default = "no" } },
          { token_endpoint_auth_method = { type = "string", required = true, default = "client_secret_post" } },
          { session_secret = { type = "string", required = false } },
          { recovery_page_path = { type = "string" } },
          { logout_path = { type = "string", required = false, default = '/logout' } },
          { redirect_after_logout_uri = { type = "string", required = false, default = '/' } },
          { filters = { type = "string" } },
          { session = {
              type = "record",
              required = false,
              fields = {
                { cookie = {
                    type = "record",
                    required = false,
                    fields = {
                      { samesite = { type = "string", required = false, default = "Lax" } },
                      { secure = { type = "boolean", default = true } }
                    }
                  }
                }
              }
            }
          },
          { discovery_override = {
              type = "record",
              required = false,
              fields = {
                { authorization_endpoint = { type = "string", required = true } },
                { token_endpoint = { type = "string", required = true } },
                { userinfo_endpoint = { type = "string", required = true } },
                { jwks_uri = { type = "string", required = true } },
                { revocation_endpoint = { type = "string", required = true } },
                { issuer = { type = "string", required = true } },
                { introspection_endpoint = { type = "string", required = false } },
                { end_session_endpoint = { type = "string", required = false  } }
              }
            }
          },
          { force_authentication_path = { type = "string" } }
        }
      }
    }
  }
}
