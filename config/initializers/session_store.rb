# frozen_string_literal: true

# SameSite must be Lax (not Strict): the IdP redirects back to /auth/result
# via a cross-site top-level GET that needs the session cookie (state/nonce).
Rails.application.config.session_store :cookie_store,
  key: "_identity_oidc_rails_session",
  same_site: :lax,
  secure: Rails.env.production?,
  httponly: true,
  expire_after: 12.hours
