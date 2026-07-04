# frozen_string_literal: true

module Api
  class HealthController < ApplicationController
    skip_forgery_protection

    def show
      render json: {
        authorization_endpoint: oidc_configuration_service.openid_configuration.fetch("authorization_endpoint"),
        private_key_fingerprint: Digest::SHA1.hexdigest(app_config.sp_private_key.to_der),
        healthy: true,
      }
    rescue StandardError => e
      render json: { error: e.inspect, healthy: false }, status: :internal_server_error
    end
  end
end
