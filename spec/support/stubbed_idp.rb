# frozen_string_literal: true

# Mirrors the WebMock setup used across the sinatra suite: a fake IdP at
# localhost:3000 with discovery, JWKS, token, and userinfo endpoints.
RSpec.shared_context "stubbed IdP" do
  let(:host) { "http://localhost:3000" }
  let(:authorization_endpoint) { "#{host}/openid/authorize" }
  let(:token_endpoint) { "#{host}/api/openid/token" }
  let(:userinfo_endpoint) { "#{host}/api/openid/userinfo" }
  let(:end_session_endpoint) { "#{host}/openid/logout" }
  let(:jwks_endpoint) { "#{host}/api/openid_connect/certs" }
  let(:client_id) { "urn:gov:gsa:openidconnect:sp:sinatra" }
  let(:idp_private_key) { OpenSSL::PKey::RSA.new(read_fixture_file("idp.key")) }
  let(:nonce) { "abc" }

  before do
    ENV["semantic_ial_values_enabled"] = "false"
    ENV["PKCE"] = "false"
    allow_any_instance_of(AppConfig).to receive(:cache_oidc_config?).and_return(false)

    stub_request(:get, "#{host}/.well-known/openid-configuration").
      to_return(body: {
        authorization_endpoint: authorization_endpoint,
        token_endpoint: token_endpoint,
        userinfo_endpoint: userinfo_endpoint,
        end_session_endpoint: end_session_endpoint,
        jwks_uri: jwks_endpoint,
      }.to_json)

    stub_request(:get, jwks_endpoint).
      to_return(body: { keys: [ {
        alg: "RS256",
        use: "sig" }.merge(JWT::JWK.new(OpenSSL::PKey::RSA.new(read_fixture_file("idp.key.pub"))).export) ],
      }.to_json)
  end

  def generate_id_token(overrides = {})
    payload = { nonce: nonce }.merge(overrides)
    JWT.encode(payload, idp_private_key, "RS256")
  end

  def stub_token_response(id_token: generate_id_token, access_token: "abc")
    stub_request(:post, token_endpoint).
      to_return(body: {
        id_token: id_token,
        access_token: access_token,
      }.to_json)
  end

  def stub_userinfo_response(userinfo = { email: "test@example.com" })
    stub_request(:get, userinfo_endpoint).
      to_return(body: userinfo.to_json)
  end
end
