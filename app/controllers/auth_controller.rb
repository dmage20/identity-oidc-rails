# frozen_string_literal: true

class AuthController < ApplicationController
  include StepUpFlow

  def request_authorization
    simulate_csp_issue_if_selected
    prompt = params[:initiate_registration] ? "create" : "select_account"

    session[:state] = SecureRandom.hex
    session[:nonce] = SecureRandom.hex
    session[:code_verifier] = SecureRandom.hex if app_config.pkce?

    ial = prepare_step_up_flow(ial: params[:ial], aal: params[:aal])

    auth_url = Oidc::AuthorizationUrlBuilder.new(
      config: app_config,
      configuration_service: oidc_configuration_service,
    ).build(
      client_id: oidc_client_id,
      state: session[:state],
      nonce: session[:nonce],
      ial: ial,
      aal: params[:aal],
      scopes: params[:requested_scopes] || [],
      code_verifier: session[:code_verifier],
      prompt: prompt,
    )

    Rails.logger.info("Redirecting to #{auth_url}")

    redirect_to auth_url, allow_other_host: true
  end

  def result
    code = params[:code]
    error = params[:error]

    return redirect_to "/?error=access_denied" if error == "access_denied"
    return render_error(error || "missing callback param: code") unless code
    return render_error("invalid state") if session[:state] != params[:state]

    token_response = Oidc::TokenExchanger.new(
      config: app_config,
      configuration_service: oidc_configuration_service,
    ).exchange(
      code: code,
      client_id: oidc_client_id,
      code_verifier: session[:code_verifier],
    )

    access_token = token_response[:access_token]
    id_token = token_response[:id_token]
    jwt = JWT.decode(
      id_token, oidc_configuration_service.idp_public_key, true, algorithm: "RS256", leeway: 10,
    ).first

    return render_error("invalid nonce") if jwt["nonce"] != session[:nonce]

    userinfo_response = Oidc::UserinfoFetcher.new(
      config: app_config,
      configuration_service: oidc_configuration_service,
    ).fetch(access_token)

    session.delete(:nonce)
    session.delete(:state)

    if session.delete(:step_up_enabled)
      aal = session.delete(:step_up_aal)

      redirect_to "/auth/request?aal=#{aal}&ial=2"
    elsif session.delete(:simulate_csp)
      redirect_to "https://www.example.com/", allow_other_host: true
    else
      session[:login_msg] = "ok"
      session[:userinfo] = userinfo_response
      session[:email] = userinfo_response[:email]

      redirect_to root_path
    end
  end

  private

  def simulate_csp_issue_if_selected
    if params[:simulate_csp]
      session[:simulate_csp] = "true"
    else
      session.delete(:simulate_csp)
    end
  end
end
