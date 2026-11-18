# frozen_string_literal: true

class AuthController < ApplicationController
  include StepUpFlow

  def request_authorization
    simulate_csp_issue_if_selected
    prompt = params[:initiate_registration] ? "create" : "select_account"

    session[:state] = SecureRandom.hex
    session[:nonce] = SecureRandom.hex
    session[:code_verifier] = SecureRandom.hex if app_config.pkce?
    if params[:dpop_jkt].present?
      session[:dpop_bound] = true
      session[:dpop_jkt] = params[:dpop_jkt]
    else
      session.delete(:dpop_bound)
      session.delete(:dpop_jkt)
    end

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
      dpop_jkt: params[:dpop_jkt],
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

    if session[:dpop_bound]
      session[:pending_oidc_code] = code
      session.delete(:state)
      return redirect_to root_path
    end

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
    jwt = decode_and_verify_id_token(id_token)

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

  # Browser-driven step 1: exchanges the authorization code with the browser's DPoP proof.
  def dpop_token
    code = session.delete(:pending_oidc_code)
    dpop_proof = params[:dpop_proof].to_s
    return render json: { error: "missing pending authorization code" }, status: :bad_request if code.blank?
    return render json: { error: "missing DPoP proof" }, status: :bad_request if dpop_proof.blank?

    token_response = Oidc::TokenExchanger.new(
      config: app_config,
      configuration_service: oidc_configuration_service,
    ).exchange(
      code: code,
      client_id: oidc_client_id,
      code_verifier: session[:code_verifier],
      dpop_proof: dpop_proof,
    )

    jwt = decode_and_verify_id_token(token_response[:id_token])
    if jwt["nonce"] != session.delete(:nonce)
      return render json: { error: "invalid nonce" }, status: :unauthorized
    end

    session[:user_sub] = jwt["sub"]
    session[:dpop_access_token] = token_response[:access_token]

    render json: {
      access_token: token_response[:access_token],
      token_type: token_response[:token_type]
    }
  end

  # Browser-driven step 2: proxies /userinfo with the browser's DPoP proof and returns the sealed
  # site_key JWE directly to the browser without storing any private key material on the server.
  def dpop_userinfo
    access_token = session[:dpop_access_token]
    dpop_proof = params[:dpop_proof].to_s
    return render json: { error: "missing access token" }, status: :unauthorized if access_token.blank?
    return render json: { error: "missing DPoP proof" }, status: :bad_request if dpop_proof.blank?

    userinfo_response = Oidc::UserinfoFetcher.new(
      config: app_config,
      configuration_service: oidc_configuration_service,
    ).fetch(access_token, dpop_proof: dpop_proof)

    session[:login_msg] = "ok"
    session[:email] = userinfo_response[:email]
    session[:user_sub] = userinfo_response[:sub]
    session[:site_key_public] = userinfo_response[:site_key_public]
    session[:userinfo] = userinfo_response.except(:site_key)

    render json: userinfo_response
  end

  private

  def decode_and_verify_id_token(id_token)
    JWT.decode(
      id_token, oidc_configuration_service.idp_public_key, true, algorithm: "RS256", leeway: 10,
    ).first
  end

  def simulate_csp_issue_if_selected
    if params[:simulate_csp]
      session[:simulate_csp] = "true"
    else
      session.delete(:simulate_csp)
    end
  end
end
