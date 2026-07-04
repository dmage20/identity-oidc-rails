# frozen_string_literal: true

require "rails_helper"

RSpec.describe AttemptsApi::ConfigurationService do
  subject(:service) { described_class.new(config: AppConfig.new) }

  let(:host) { "http://localhost:3000" }
  let(:configuration_uri) { "#{host}/.well-known/ssf-configuration" }

  before do
    stub_request(:get, configuration_uri).
      to_return(body: { jwks_uri: "#{host}/api/attempts/certs" }.to_json)
  end

  it "raises an AppError if the request fails" do
    stub_request(:get, configuration_uri).
      to_return(body: "", status: 500)

    expect { service.ssf_configuration }.to raise_error(
      AppError, /Unable to retrieve Attempts API configuration/,
    )
  end

  it "parses the ssf configuration" do
    expect(service.ssf_configuration[:jwks_uri]).to eq("#{host}/api/attempts/certs")
  end

  context "when caching" do
    before do
      allow(Rails).to receive(:cache).and_return(ActiveSupport::Cache::MemoryStore.new)
    end

    it "does not make more than one HTTP request" do
      service.ssf_configuration
      service.ssf_configuration

      expect(a_request(:get, configuration_uri)).to have_been_made.once
    end
  end
end
