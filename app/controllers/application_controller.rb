# frozen_string_literal: true

class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception

  rescue_from AppError do |e|
    render_error(e.message, status: :internal_server_error)
  end

  rescue_from Faraday::ConnectionFailed, Errno::ECONNREFUSED do |e|
    render_error(e.inspect, status: :internal_server_error)
  end

  private

  def app_config
    AppConfig.instance
  end

  def oidc_configuration_service
    @oidc_configuration_service ||= Oidc::ConfigurationService.new(config: app_config)
  end

  # The sinatra app rendered state/nonce validation failures as a 200 error
  # page and only exceptions as 500 — preserved here for parity.
  def render_error(error, status: :ok)
    render "errors/show", locals: { error: error }, status: status
  end

  # PKCE clients and the mock-IRS session use dedicated client ids.
  def oidc_client_id
    return app_config.mock_irs_client_id if session[:irs]

    app_config.pkce? ? app_config.client_id_pkce : app_config.client_id
  end
end
