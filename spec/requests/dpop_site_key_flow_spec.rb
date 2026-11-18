# frozen_string_literal: true

require "rails_helper"

RSpec.describe "America.gov DPoP + site_key + JSON conversation flow", type: :request do
  include_context "stubbed IdP"

  let(:tmp_store) { Rails.root.join("tmp", "test_america_gov_conversations_#{SecureRandom.hex(4)}.json") }
  let(:dpop_key) { OpenSSL::PKey::EC.generate("prime256v1") }
  let(:dpop_jwk) { JWT::JWK.new(dpop_key).export }
  let(:dpop_jkt) do
    canonical = { crv: dpop_jwk[:crv], kty: dpop_jwk[:kty], x: dpop_jwk[:x], y: dpop_jwk[:y] }.to_json
    Base64.urlsafe_encode64(Digest::SHA256.digest(canonical), padding: false)
  end

  before do
    ENV["PKCE"] = "true"
    allow(AmericaGov::ConversationStore).to receive(:new).and_wrap_original do |orig, **kwargs|
      orig.call(path: kwargs.fetch(:path, tmp_store))
    end
  end

  after do
    ENV["PKCE"] = "false"
    FileUtils.rm_f(tmp_store)
  end

  it "runs the DPoP authorization, token, userinfo, and server-sealed JSON store flow" do
    get "/auth/request", params: { requested_scopes: %w[email site_key], dpop_jkt: dpop_jkt }
    expect(response).to have_http_status(:redirect)

    query = Rack::Utils.parse_query(URI.parse(response.location).query)
    expect(query["dpop_jkt"]).to eq(dpop_jkt)
    expect(query["code_challenge"]).to match(/\A[A-Za-z0-9_-]{43}\z/)
    expect(query["scope"]).to eq("email site_key openid")

    get "/auth/result", params: { code: "code-123", state: query["state"] }
    expect(response).to redirect_to(root_path)

    token_stub = stub_request(:post, token_endpoint).
      with(headers: { "DPoP" => "proof-token" }).
      to_return(body: {
        access_token: "dpop-access-token",
        token_type: "DPoP",
        id_token: generate_id_token(nonce: query["nonce"], sub: "user-sub-42")
      }.to_json)

    post "/auth/dpop_token", params: { dpop_proof: "proof-token" }
    expect(response).to have_http_status(:ok)
    expect(token_stub).to have_been_requested.once
    expect(JSON.parse(response.body)["access_token"]).to eq("dpop-access-token")

    site_key = OpenSSL::PKey::EC.generate("prime256v1")
    site_pub_jwk = JWT::JWK.new(site_key).export.slice(:kty, :crv, :x, :y)

    userinfo_stub = stub_request(:get, userinfo_endpoint).
      with(headers: { "Authorization" => "DPoP dpop-access-token", "DPoP" => "proof-userinfo" }).
      to_return(body: {
        sub: "user-sub-42",
        email: "resident@america.gov",
        site_key: "sealed.jwe.iv.ct.tag",
        site_key_public: site_pub_jwk
      }.to_json)

    post "/auth/dpop_userinfo", params: { dpop_proof: "proof-userinfo" }
    expect(response).to have_http_status(:ok)
    expect(userinfo_stub).to have_been_requested.once
    expect(JSON.parse(response.body)["site_key"]).to eq("sealed.jwe.iv.ct.tag")

    # Save a browser-encrypted ciphertext record
    post "/api/conversations", params: {
      conversation: {
        kind: "chat",
        source: "browser",
        epk: site_pub_jwk,
        iv: "iv123",
        aad: "aad123",
        ciphertext: "ciphertext-only-no-plaintext"
      }
    }
    expect(response).to have_http_status(:created)

    # Simulate an offline server-sealed ticket using site_key_public
    post "/api/conversations/server_sealed"
    expect(response).to have_http_status(:created)

    get "/api/conversations"
    expect(response).to have_http_status(:ok)
    body = JSON.parse(response.body)
    expect(body["items"].length).to eq(2)
    expect(body["raw_store_json"]).not_to include("SSA eligibility")

    # Verify the browser's private site key can decrypt the server-sealed ciphertext
    sealed_item = body["items"].last
    epk = JWT::JWK.import(sealed_item["epk"].transform_keys(&:to_sym)).verify_key
    shared = site_key.dh_compute_key(epk.public_key)
    aes_key = OpenSSL::Digest::SHA256.digest(
      [ 1 ].pack("N") + shared + [ "user-sub-42".bytesize ].pack("N") + "user-sub-42" + "A256GCM",
    )
    raw_ct = Base64.urlsafe_decode64(sealed_item["ciphertext"])
    cipher = OpenSSL::Cipher.new("aes-256-gcm").decrypt
    cipher.key = aes_key
    cipher.iv = Base64.urlsafe_decode64(sealed_item["iv"])
    cipher.auth_tag = raw_ct.byteslice(-16, 16)
    cipher.auth_data = sealed_item["aad"]
    decrypted = JSON.parse(cipher.update(raw_ct.byteslice(0...-16)) + cipher.final)
    expect(decrypted["kind"]).to eq("offline_case_summary")
    expect(decrypted["body"]).to include("Automated SSA eligibility")

    delete "/api/conversations"
    expect(response).to have_http_status(:ok)
    expect(JSON.parse(response.body)["items"]).to eq([])
  end
end
