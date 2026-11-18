# frozen_string_literal: true

module Oidc
  # Exchanges an authorization code for tokens. Client authentication is
  # private_key_jwt by default, or PKCE (code_verifier) when enabled.
  class TokenExchanger
    JWT_CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

    def initialize(config: AppConfig.instance, configuration_service: ConfigurationService.new(config: config))
      @config = config
      @configuration_service = configuration_service
    end

    # @return [HashWithIndifferentAccess] the token endpoint response
    def exchange(code:, client_id:, code_verifier: nil, dpop_proof: nil)
      token_params = {
        grant_type: "authorization_code",
        code: code
      }

      if @config.pkce?
        token_params[:code_verifier] = code_verifier
      else
        token_params[:client_assertion_type] = JWT_CLIENT_ASSERTION_TYPE
        token_params[:client_assertion] = client_assertion_jwt(client_id)
      end

      headers = dpop_proof.present? ? { "DPoP" => dpop_proof } : {}
      response = FaradayConnection.build(url: token_endpoint, headers: headers).post(nil, token_params)
      FaradayConnection.log_failure(response, token_endpoint)
      raise AppError.new(response.body) if response.status != 200

      JSON.parse(response.body).with_indifferent_access
    end

    private

    def token_endpoint
      @configuration_service.openid_configuration[:token_endpoint]
    end

    def client_assertion_jwt(client_id)
      jwt_payload = {
        iss: client_id,
        sub: client_id,
        aud: token_endpoint,
        jti: SecureRandom.hex,
        exp: Time.now.to_i + 1000
      }

      JWT.encode(jwt_payload, @config.sp_private_key, "RS256")
    end
  end
end
