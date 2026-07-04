# frozen_string_literal: true

module AttemptsApi
  # Masks event values not on the plaintext allowlist. Attempt events carry
  # PII; only operational metadata is shown unless the deployment explicitly
  # opts in to plaintext.
  class Redactor
    ALLOWED_PLAINTEXT_KEYS = %w[
      application_url
      aws_region
      client_port
      client_user_agent
      email_already_registered
      failure_reason
      language
      mfa_device_type
      occurred_at
      otp_delivery_method
      rate_limit_type
      reauthentication
      reproof
      resend
      success
      unique_session_id
      user_agent
    ].freeze

    def initialize(config: AppConfig.instance)
      @config = config
    end

    def event_data(event_values)
      return event_values.first if @config.allow_all_events_plaintext?

      redact(event_values.first)
    end

    private

    def redact(data)
      data.each_with_object({}) do |(key, value), result|
        result[key] = if value.is_a?(Hash)
          redact(value)
        elsif ALLOWED_PLAINTEXT_KEYS.include?(key)
          value
        else
          "REDACTED"
        end
      end
    end
  end
end
