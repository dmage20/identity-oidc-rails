# frozen_string_literal: true

module Oidc
  # Fetches user attributes from the userinfo endpoint with a Bearer token.
  class UserinfoFetcher
    def initialize(config: AppConfig.instance, configuration_service: ConfigurationService.new(config: config))
      @configuration_service = configuration_service
    end

    # Fetches user attributes from the userinfo endpoint with a Bearer or DPoP token.
    def fetch(access_token, dpop_proof: nil)
      url = @configuration_service.openid_configuration[:userinfo_endpoint]

      headers = if dpop_proof.present?
        { "Authorization" => "DPoP #{access_token}", "DPoP" => dpop_proof }
      else
        { "Authorization" => "Bearer #{access_token}" }
      end

      connection = FaradayConnection.build(
        url: url,
        headers: headers,
      )

      response = connection.get("")
      FaradayConnection.log_failure(response, url)
      raise AppError.new(response.body) if response.status != 200

      JSON.parse(response.body).with_indifferent_access
    end
  end
end
