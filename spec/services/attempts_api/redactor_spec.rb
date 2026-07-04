# frozen_string_literal: true

require "rails_helper"

RSpec.describe AttemptsApi::Redactor do
  subject(:redactor) { described_class.new(config: AppConfig.new) }

  let(:event) do
    [
      {
        "application_url" => "http://example.com",
        "aws_region" => "us-west-2",
        "client_port" => "3000",
        "client_user_agent" => "Mozilla/5.0",
        "pii_event" => "here is some pii",
        "nested" => {
          "first_name" => "more pii",
          "success" => {
            "more_pii" => "recursive pii"
          }
        }
      }
    ]
  end

  context "when the config allows plaintext events" do
    before { ENV["allow_all_events_plaintext"] = "true" }
    after { ENV.delete("allow_all_events_plaintext") }

    it "returns the event data as is" do
      expect(redactor.event_data(event)).to eq(event.first)
    end
  end

  context "when the config does not allow plaintext events" do
    before { ENV["allow_all_events_plaintext"] = "false" }
    after { ENV.delete("allow_all_events_plaintext") }

    it "returns the event data with sensitive information masked" do
      masked_event = event.first.merge(
        {
          "pii_event" => "REDACTED",
          "nested" => {
            "first_name" => "REDACTED",
            "success" => { "more_pii" => "REDACTED" }
          }
        },
      )

      expect(redactor.event_data(event)).to eq(masked_event)
    end
  end
end
