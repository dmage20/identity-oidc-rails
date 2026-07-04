# frozen_string_literal: true

module AttemptsApi
  # Polls the IdP's Attempts API for security events; passing jtis in `ack`
  # acknowledges (deletes) those events.
  class Client
    MAX_EVENTS = 100

    def initialize(config: AppConfig.instance, client_id:, decryptor: EventDecryptor.new(config: config))
      @config = config
      @client_id = client_id
      @decryptor = decryptor
    end

    # @return [Array<Hash>] decrypted Security Event Token payloads
    def poll(ack: nil)
      auth = "Bearer #{@client_id} #{@config.attempts_shared_secret}"

      connection = FaradayConnection.build(
        url: @config.attempts_url,
        params: { maxEvents: MAX_EVENTS, ack: ack }.compact,
        headers: { "Authorization" => auth },
      )

      # The sinatra app issued this POST twice (status check + body read),
      # double-polling the API; a single request does both.
      response = connection.post
      FaradayConnection.log_failure(response, @config.attempts_url)
      raise AppError.new(response.body) if response.status != 200

      sets = JSON.parse(response.body)["sets"]

      sets.values.map { |jwe| @decryptor.decrypt(jwe) }
    end
  end
end
