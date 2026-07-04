# frozen_string_literal: true

require "rails_helper"

RSpec.describe "GET /api/health", type: :request do
  include_context "stubbed IdP"

  it "returns the authorization endpoint and key fingerprint" do
    get "/api/health"

    expect(response).to have_http_status(:ok)

    body = JSON.parse(response.body)
    expect(body["authorization_endpoint"]).to eq(authorization_endpoint)
    expect(body["private_key_fingerprint"]).to match(/\A\h{40}\z/)
    expect(body["healthy"]).to be(true)
  end

  it "returns unhealthy with a 500 when the IdP is unreachable" do
    stub_request(:get, "#{host}/.well-known/openid-configuration").
      to_return(status: 500)

    get "/api/health"

    expect(response).to have_http_status(:internal_server_error)
    body = JSON.parse(response.body)
    expect(body["healthy"]).to be(false)
    expect(body["error"]).to be_present
  end

  it "renders failure_to_proof" do
    get "/failure_to_proof"

    expect(response.body).to include("We were unable to verify your identity.")
  end
end
