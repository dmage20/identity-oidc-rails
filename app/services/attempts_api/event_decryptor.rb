# frozen_string_literal: true

module AttemptsApi
  # Decrypts a JWE-encrypted attempt event, optionally verifying its ES256
  # signature when the IdP signs events.
  class EventDecryptor
    def initialize(config: AppConfig.instance, configuration_service: ConfigurationService.new(config: config))
      @config = config
      @configuration_service = configuration_service
    end

    # @return [Hash] the decrypted Security Event Token payload
    def decrypt(jwe)
      payload = JWE.decrypt(jwe, @config.sp_private_key)

      if @config.signed_events?
        JWT.decode(
          payload,
          @configuration_service.attempts_public_key,
          true,
          { algorithm: "ES256" },
        ).first
      else
        # The sinatra app skipped this parse and leaned on String#[] substring
        # lookups in the view; parse explicitly so both modes yield a Hash.
        JSON.parse(payload)
      end
    end
  end
end
