# frozen_string_literal: true

class HomeController < ApplicationController
  include StepUpFlow

  def index
    @login_msg = session.delete(:login_msg)
    @logout_msg = session.delete(:logout_msg)
    @user_email = session[:email]
    @user_sub = session[:user_sub]
    @userinfo = session.delete(:userinfo)
    @pending_dpop_code = session[:pending_oidc_code].present?
    @dpop_jkt = session[:dpop_jkt]
    @site_key_public = session[:site_key_public]

    @aal = params[:aal]
    @ial = prepare_step_up_flow(ial: params[:ial], aal: @aal)
    @access_denied = params[:error] == "access_denied"

    # Touches the discovery endpoint so IdP connectivity problems surface on
    # the home page, exactly as the sinatra app did.
    @openid_config = oidc_configuration_service.openid_configuration
    @america_gov_config = {
      pendingDpop: @pending_dpop_code,
      clientId: oidc_client_id,
      userSub: @user_sub,
      userEmail: @user_email,
      dpopJkt: @dpop_jkt,
      siteKeyPublic: @site_key_public,
      tokenEndpoint: @openid_config[:token_endpoint],
      userinfoEndpoint: @openid_config[:userinfo_endpoint]
    }
  end

  def failure_to_proof
  end
end
