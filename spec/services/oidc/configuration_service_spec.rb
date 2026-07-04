# frozen_string_literal: true

require "rails_helper"

RSpec.describe Oidc::ConfigurationService do
  subject(:service) { described_class.new(config: AppConfig.new) }

  let(:host) { "http://localhost:3000" }
  let(:configuration_uri) { "#{host}/.well-known/openid-configuration" }

  before do
    stub_request(:get, configuration_uri).
      to_return(body: {
        authorization_endpoint: "#{host}/openid/authorize",
        token_endpoint: "#{host}/api/openid/token",
        jwks_uri: "#{host}/api/openid/certs",
        end_session_endpoint: "#{host}/openid/logout"
      }.to_json)
  end

  it "raises an AppError if the request fails" do
    stub_request(:get, configuration_uri).
      to_return(body: "", status: 401)

    expect { service.openid_configuration }.to raise_error(AppError)
  end

  it "parses the discovery document" do
    expect(service.openid_configuration[:token_endpoint]).to eq("#{host}/api/openid/token")
  end

  context "when caching is enabled" do
    before do
      allow(Rails).to receive(:cache).and_return(ActiveSupport::Cache::MemoryStore.new)
    end

    it "does not make more than one HTTP request" do
      first = service.openid_configuration
      second = service.openid_configuration

      expect(first).to eq(second)
      expect(a_request(:get, configuration_uri)).to have_been_made.once
    end
  end

  context "when caching is disabled" do
    before do
      allow_any_instance_of(AppConfig).to receive(:cache_oidc_config?).and_return(false)
    end

    it "fetches the configuration on every call" do
      service.openid_configuration
      service.openid_configuration

      expect(a_request(:get, configuration_uri)).to have_been_made.twice
    end
  end
end
