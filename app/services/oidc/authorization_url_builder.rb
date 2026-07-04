# frozen_string_literal: true

module Oidc
  # Builds the authorization request URL sent to the IdP.
  class AuthorizationUrlBuilder
    def initialize(config: AppConfig.instance, configuration_service: ConfigurationService.new(config: config))
      @config = config
      @configuration_service = configuration_service
    end

    def build(client_id:, state:, nonce:, ial:, aal:, scopes:, prompt:, code_verifier: nil)
      endpoint = @configuration_service.openid_configuration[:authorization_endpoint]

      request_params = {
        client_id: client_id,
        response_type: "code",
        acr_values: AcrValues.build(ial: ial, aal: aal, config: @config),
        scope: scopes.join(" ") + " openid",
        redirect_uri: File.join(@config.redirect_uri, "/auth/result"),
        state: state,
        nonce: nonce,
        attempts_api_session_id: SecureRandom.uuid,
        prompt: prompt,
      }

      if code_verifier
        request_params[:code_challenge] = url_safe_code_challenge(code_verifier)
        request_params[:code_challenge_method] = "S256"
      end

      "#{endpoint}?#{request_params.compact.to_query}"
    end

    private

    def url_safe_code_challenge(code_verifier)
      Base64.urlsafe_encode64(Digest::SHA256.digest(code_verifier))
    end
  end
end
