# frozen_string_literal: true

module Oidc
  # Fetches the IdP's OIDC discovery document and signing key. Responses are
  # cached (per-process memory store) unless cache_oidc_config is disabled.
  class ConfigurationService
    CONFIG_CACHE_KEY = "oidc/openid-configuration"
    KEY_CACHE_KEY = "oidc/idp-public-key"

    def initialize(config: AppConfig.instance)
      @config = config
    end

    def openid_configuration
      if @config.cache_oidc_config?
        Rails.cache.fetch(CONFIG_CACHE_KEY) { live_configuration }
      else
        live_configuration
      end
    end

    # @return [OpenSSL::PKey::RSA] the IdP's ID-token signing key from JWKS
    def idp_public_key
      if @config.cache_oidc_config?
        Rails.cache.fetch(KEY_CACHE_KEY) { live_idp_public_key }
      else
        live_idp_public_key
      end
    end

    private

    def live_configuration
      url = URI.join(@config.idp_url, "/.well-known/openid-configuration")
      response = FaradayConnection.get(url)

      unless response.status == 200
        msg = "Error: Unable to retrieve OIDC configuration from IdP."
        msg += " #{@config.idp_url} responded with #{response.status}."
        msg += " Perhaps we need to reimplement HTTP Basic Auth." if response.status == 401

        raise AppError.new(msg)
      end

      JSON.parse(response.body).with_indifferent_access
    end

    def live_idp_public_key
      certs_response = JSON.parse(
        FaradayConnection.get(openid_configuration[:jwks_uri]).body,
      ).with_indifferent_access

      JSON::JWK.new(certs_response[:keys].first).to_key
    end
  end
end
