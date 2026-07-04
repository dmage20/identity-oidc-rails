# frozen_string_literal: true

require "rails_helper"

# End-to-end request flow against the stubbed IdP: authorization request,
# callback with code, token exchange, userinfo, and logout round-trip.
RSpec.describe "OIDC auth flow", type: :request do
  include_context "stubbed IdP"

  it "redirects /auth/request to the IdP with IAL1 defaults" do
    get "/auth/request", params: { requested_scopes: %w[email x509] }

    expect(response).to have_http_status(:redirect)

    location = URI.parse(response.location)
    expect(location.to_s).to start_with(authorization_endpoint)

    query = Rack::Utils.parse_query(location.query)
    expect(query["client_id"]).to eq(client_id)
    expect(query["response_type"]).to eq("code")
    expect(query["acr_values"]).to eq("http://idmanagement.gov/ns/assurance/ial/1")
    expect(query["scope"]).to eq("email x509 openid")
    expect(query["redirect_uri"]).to eq("http://localhost:9292/auth/result")
    expect(query["state"]).to be_present
    expect(query["nonce"]).to be_present
    expect(query["prompt"]).to eq("select_account")
    expect(query["attempts_api_session_id"]).to match(/\A\h{8}-\h{4}-\h{4}-\h{4}-\h{12}\z/)
  end

  it "completes the callback: token exchange, nonce check, userinfo, home redirect" do
    get "/auth/request"
    query = Rack::Utils.parse_query(URI.parse(response.location).query)
    state = query["state"]
    idp_nonce = query["nonce"]

    stub_token_response(id_token: generate_id_token(nonce: idp_nonce))
    stub_userinfo_response(email: "test@example.com", given_name: "Testy")

    get "/auth/result", params: { code: "abc123", state: state }

    expect(response).to redirect_to("/")

    follow_redirect!
    expect(response.body).to include("Login was a Success!")
    expect(response.body).to include("test@example.com")
  end

  it "renders an error page for an invalid state" do
    get "/auth/request"

    get "/auth/result", params: { code: "abc123", state: "wrong" }

    expect(response.body).to include("invalid state")
  end

  it "logs out through the IdP end_session_endpoint" do
    post "/handle-logout"

    expect(response).to have_http_status(:redirect)
    location = URI.parse(response.location)
    expect(location.to_s).to start_with(end_session_endpoint)

    query = Rack::Utils.parse_query(location.query)
    expect(query["client_id"]).to eq(client_id)
    expect(query["post_logout_redirect_uri"]).to eq("http://localhost:9292/logout")
    expect(query["state"]).to be_present
  end
end
