# frozen_string_literal: true

module AttemptsApi
  # Fetches the IdP's SSF (Shared Signals Framework) configuration and the
  # ES256 key used to verify signed attempt events.
  class ConfigurationService
    CONFIG_CACHE_KEY = "attempts/ssf-configuration"
    KEY_CACHE_KEY = "attempts/public-key"

    def initialize(config: AppConfig.instance)
      @config = config
    end

    def ssf_configuration
      Rails.cache.fetch(CONFIG_CACHE_KEY) { live_configuration }
    end

    def attempts_public_key
      Rails.cache.fetch(KEY_CACHE_KEY) { live_attempts_public_key }
    end

    private

    def live_configuration
      url = URI.join(@config.idp_url, "/.well-known/ssf-configuration")
      response = FaradayConnection.get(url)

      unless response.status == 200
        msg = "Error: Unable to retrieve Attempts API configuration from IdP."
        msg += " #{@config.idp_url} responded with #{response.status}."

        raise AppError.new(msg)
      end

      JSON.parse(response.body).with_indifferent_access
    end

    def live_attempts_public_key
      certs_response = JSON.parse(
        FaradayConnection.get(ssf_configuration[:jwks_uri]).body,
      ).with_indifferent_access

      JWT::JWK.import(certs_response[:keys].first).keypair
    end
  end
end
