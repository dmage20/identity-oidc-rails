# frozen_string_literal: true

module Oidc
  # Fetches user attributes from the userinfo endpoint with a Bearer token.
  class UserinfoFetcher
    def initialize(config: AppConfig.instance, configuration_service: ConfigurationService.new(config: config))
      @configuration_service = configuration_service
    end

    # @return [HashWithIndifferentAccess]
    def fetch(access_token)
      url = @configuration_service.openid_configuration[:userinfo_endpoint]

      connection = FaradayConnection.build(
        url: url,
        headers: { "Authorization" => "Bearer #{access_token}" },
      )

      JSON.parse(connection.get("").body).with_indifferent_access
    end
  end
end
