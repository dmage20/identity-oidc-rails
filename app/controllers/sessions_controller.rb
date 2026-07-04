# frozen_string_literal: true

class SessionsController < ApplicationController
  def destroy
    session.delete(:userinfo)
    session.delete(:email)
    session.delete(:step_up_enabled)
    session.delete(:step_up_aal)
    session.delete(:irs)

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
