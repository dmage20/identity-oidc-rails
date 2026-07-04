# frozen_string_literal: true

require "aws-sdk-secretsmanager"

# Application configuration, sourced from environment variables. Environment
# variable names are kept identical to the identity-oidc-sinatra app so a
# deployment can switch implementations with zero config changes.
class AppConfig
  class << self
    def instance
      @instance ||= new
    end

    # Test hook: clears memoized config (and the memoized private key).
    def reset!
      @instance = nil
    end
  end

  def initialize
    @config = default_config
  end

  def attempts_shared_secret
    @config.fetch("attempts_shared_secret")
  end

  def attempts_url
    "#{idp_url}/api/attempts/poll"
  end

  def allow_all_events_plaintext?
    @config.fetch("allow_all_events_plaintext") == "true"
  end

  def idp_url
    @config.fetch("idp_url")
  end

  def redirect_uri
    @config.fetch("redirect_uri")
  end

  def client_id
    @config.fetch("client_id")
  end

  def client_id_pkce
    @config.fetch("client_id_pkce")
  end

  def mock_irs_client_id
    @config.fetch("mock_irs_client_id")
  end

  def redact_ssn?
    @config.fetch("redact_ssn")
  end

  def signed_events?
    @config.fetch("signed_events") == "true"
  end

  def cache_oidc_config?
    @config.fetch("cache_oidc_config")
  end

  def eipp_allowed?
    @config.fetch("eipp_allowed")
  end

  def pkce?
    ENV["PKCE"] == "true"
  end

  def semantic_ial_values_enabled?
    ENV["semantic_ial_values_enabled"] == "true"
  end

  # @return [OpenSSL::PKey::RSA]
  def sp_private_key
    return @sp_private_key if @sp_private_key

    key = ENV["sp_private_key"] || sp_private_key_raw(@config.fetch("sp_private_key_path"))
    @sp_private_key = OpenSSL::PKey::RSA.new(key)
  end

  private

  def default_config
    data = {
      "client_id" => ENV["client_id"] || "urn:gov:gsa:openidconnect:sp:sinatra",
      "client_id_pkce" => ENV["client_id_pkce"] || "urn:gov:gsa:openidconnect:sp:sinatra_pkce",
      "mock_irs_client_id" => ENV["mock_irs_client_id"] ||
                              "urn:gov:gsa:openidconnect:sp:mock_irs",
      "redirect_uri" => ENV["redirect_uri"] || "http://localhost:9292/",
      "sp_private_key_path" => ENV["sp_private_key_path"] || Rails.root.join("config/demo_sp.key").to_s,
      "redact_ssn" => true,
      "cache_oidc_config" => true,
      "eipp_allowed" => ENV.fetch("eipp_allowed", "false") == "true",
      "attempts_shared_secret" => ENV["attempts_shared_secret"],
      "allow_all_events_plaintext" => ENV["allow_all_events_plaintext"],
      "signed_events" => ENV["signed_events"]
    }

    env = ENV["idp_environment"] || "int"
    domain = ENV["idp_domain"] || "identitysandbox.gov"

    data["idp_url"] = ENV.fetch("idp_url", nil)
    unless data["idp_url"]
      data["idp_url"] = if env == "prod"
        "https://secure.#{domain}"
      else
        "https://idp.#{env}.#{domain}"
      end
    end

    data
  end

  def sp_private_key_raw(path)
    if path.start_with?("aws-secretsmanager:")
      secret_id = path.split(":", 2).fetch(1)
      smc = Aws::SecretsManager::Client.new
      begin
        return smc.get_secret_value(secret_id: secret_id).secret_string
      rescue Aws::SecretsManager::Errors::ResourceNotFoundException
        raise if ENV["deployed"]
      end

      Rails.logger.warn("#{secret_id.inspect}: not found in AWS Secrets Manager, using demo key")
      sp_private_key_raw(demo_private_key_path)
    else
      File.read(path)
    end
  end

  def demo_private_key_path
    Rails.root.join("config/demo_sp.key").to_s
  end
end
