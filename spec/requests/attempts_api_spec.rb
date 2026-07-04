# frozen_string_literal: true

require "rails_helper"

RSpec.describe "Attempts API", type: :request do
  include_context "stubbed IdP"

  let(:attempts_url) { "#{host}/api/attempts/poll" }
  let(:sp_public_key) { AppConfig.new.sp_private_key.public_key }

  let(:event_payload) do
    {
      "jti" => "jti-123",
      "iat" => 1_700_000_000,
      "events" => {
        "https://schemas.login.gov/secevent/attempts/event-type/login-success" => {
          "success" => true,
          "occurred_at" => 1_700_000_000,
          "pii_thing" => "secret value",
        },
      },
    }
  end

  def encrypt_event(payload)
    JWE.encrypt(payload.to_json, sp_public_key, alg: "RSA-OAEP")
  end

  before do
    ENV["attempts_shared_secret"] = "test-shared-secret"
    ENV["signed_events"] = "false"
  end

  after do
    ENV.delete("attempts_shared_secret")
    ENV.delete("signed_events")
  end

  describe "GET /attempts-api" do
    it "lists decrypted events with PII redacted" do
      stub_request(:post, attempts_url).
        with(
          query: { maxEvents: 100 },
          headers: { "Authorization" => "Bearer #{client_id} test-shared-secret" },
        ).
        to_return(body: { sets: { "jti-123" => encrypt_event(event_payload) } }.to_json)

      get "/attempts-api"

      expect(response).to have_http_status(:ok)
      expect(response.body).to include("login-success")
      expect(response.body).to include("jti-123")
      expect(response.body).to include("REDACTED")
      expect(response.body).not_to include("secret value")
    end

    it "shows plaintext events when allowed" do
      ENV["allow_all_events_plaintext"] = "true"

      stub_request(:post, attempts_url).
        with(query: { maxEvents: 100 }).
        to_return(body: { sets: { "jti-123" => encrypt_event(event_payload) } }.to_json)

      get "/attempts-api"

      expect(response.body).to include("secret value")
    ensure
      ENV.delete("allow_all_events_plaintext")
    end

    it "renders a 500 when the Attempts API rejects the request" do
      stub_request(:post, attempts_url).
        with(query: { maxEvents: 100 }).
        to_return(status: 401, body: "unauthorized")

      get "/attempts-api"

      expect(response).to have_http_status(:internal_server_error)
      expect(response.body).to include("unauthorized")
    end

    context "with signed events" do
      let(:signing_key) { OpenSSL::PKey::EC.generate("prime256v1") }

      it "verifies the ES256 signature before rendering" do
        ENV["signed_events"] = "true"

        jwt = JWT.encode(event_payload, signing_key, "ES256")
        encrypted_jwt = JWE.encrypt(jwt, sp_public_key, alg: "RSA-OAEP")

        stub_request(:get, "#{host}/.well-known/ssf-configuration").
          to_return(body: { jwks_uri: "#{host}/api/attempts/certs" }.to_json)
        stub_request(:get, "#{host}/api/attempts/certs").
          to_return(body: { keys: [ JWT::JWK.new(signing_key).export ] }.to_json)
        stub_request(:post, attempts_url).
          with(query: { maxEvents: 100 }).
          to_return(body: { sets: { "jti-123" => encrypted_jwt } }.to_json)

        get "/attempts-api"

        expect(response).to have_http_status(:ok)
        expect(response.body).to include("jti-123")
      end
    end
  end

  describe "POST /ack-events" do
    it "acknowledges the given jtis and redirects back" do
      ack_stub = stub_request(:post, attempts_url).
        with(query: { maxEvents: 100, ack: %w[jti-1 jti-2] }).
        to_return(body: { sets: {} }.to_json)

      post "/ack-events", params: { jtis: "jti-1,jti-2" }

      expect(response).to redirect_to("/attempts-api")
      expect(ack_stub).to have_been_requested.once
    end
  end
end
