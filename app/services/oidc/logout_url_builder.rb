# frozen_string_literal: true

module Oidc
  # Builds the RP-initiated logout URL (end_session_endpoint).
  class LogoutUrlBuilder
    def initialize(config: AppConfig.instance, configuration_service: ConfigurationService.new(config: config))
      @config = config
      @configuration_service = configuration_service
    end

    def build(client_id:)
      endpoint = @configuration_service.openid_configuration[:end_session_endpoint]
      request_params = {
        client_id: client_id,
        post_logout_redirect_uri: File.join(@config.redirect_uri, "logout"),
        state: SecureRandom.hex,
      }.to_query

      "#{endpoint}?#{request_params}"
    end
  end
end
