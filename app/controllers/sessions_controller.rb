# frozen_string_literal: true

class SessionsController < ApplicationController
  def destroy
    %i[
      userinfo
      email
      user_sub
      site_key_public
      dpop_bound
      dpop_jkt
      dpop_access_token
      pending_oidc_code
      step_up_enabled
      step_up_aal
      irs
    ].each { |key| session.delete(key) }

    logout_url = Oidc::LogoutUrlBuilder.new(
      config: app_config,
      configuration_service: oidc_configuration_service,
    ).build(client_id: oidc_client_id)

    redirect_to logout_url, allow_other_host: true
  end

  def logged_out
    session[:logout_msg] = "ok"
    redirect_to root_path
  end
end
