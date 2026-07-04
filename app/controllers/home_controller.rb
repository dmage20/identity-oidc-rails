# frozen_string_literal: true

class HomeController < ApplicationController
  include StepUpFlow

  def index
    @login_msg = session.delete(:login_msg)
    @logout_msg = session.delete(:logout_msg)
    @user_email = session[:email]
    @userinfo = session.delete(:userinfo)

    @aal = params[:aal]
    @ial = prepare_step_up_flow(ial: params[:ial], aal: @aal)
    @access_denied = params[:error] == "access_denied"

    # Touches the discovery endpoint so IdP connectivity problems surface on
    # the home page, exactly as the sinatra app did.
    oidc_configuration_service.openid_configuration
  end

  def failure_to_proof
  end
end
