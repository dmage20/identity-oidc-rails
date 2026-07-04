# frozen_string_literal: true

require "rails_helper"

RSpec.describe "Token exchange details", type: :request do
  include_context "stubbed IdP"

  let(:code) { "abc-code" }
  let(:bearer_token) { "abc" }
  let(:email) { "foobar@bar.com" }

  def perform_auth_request
    get "/auth/request"
    Rack::Utils.parse_query(URI.parse(response.location).query)
  end

  it "authenticates with a private_key_jwt client assertion" do
    query = perform_auth_request

    token_stub = stub_request(:post, token_endpoint).
      with(body: {
        grant_type: "authorization_code",
        code: code,
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: kind_of(String)
      }).
      to_return(body: {
        access_token: bearer_token,
        id_token: generate_id_token(nonce: query["nonce"])
      }.to_json)
    stub_request(:get, userinfo_endpoint).
      with(headers: { "Authorization" => "Bearer #{bearer_token}" }).
      to_return(body: { email: email }.to_json)

    get "/auth/result", params: { code: code, state: query["state"] }

    expect(token_stub).to have_been_requested.once
    follow_redirect!
    expect(response.body).to include(email)
  end

  it "escapes dangerous HTML in the userinfo" do
    dangerous_email = '<script>alert("hi")</script> mallory@bar.com'
    query = perform_auth_request

    stub_token_response(id_token: generate_id_token(nonce: query["nonce"]))
    stub_userinfo_response(email: dangerous_email)

    get "/auth/result", params: { code: code, state: query["state"] }
    follow_redirect!

    expect(response.body).not_to include(dangerous_email)
    expect(response.body).to include("&lt;script&gt;alert(&quot;hi&quot;)&lt;/script&gt; mallory@bar.com")
  end

  it "shows a logout form posting to /handle-logout once logged in" do
    query = perform_auth_request

    stub_token_response(id_token: generate_id_token(nonce: query["nonce"]))
    stub_userinfo_response(email: email)

    get "/auth/result", params: { code: code, state: query["state"] }
    follow_redirect!

    doc = Nokogiri::HTML(response.body)
    logout_form = doc.at_css("form")
    expect(logout_form).not_to be_nil
    expect(logout_form[:action]).to eq "/handle-logout"
    expect(logout_form[:method]).to eq "post"
  end

  context "with PKCE enabled" do
    before { ENV["PKCE"] = "true" }
    after { ENV["PKCE"] = "false" }

    it "exchanges the code with the code_verifier" do
      query = perform_auth_request

      token_stub = stub_request(:post, token_endpoint).
        with(body: {
          grant_type: "authorization_code",
          code: code,
          code_verifier: kind_of(String)
        }).
        to_return(body: {
          access_token: bearer_token,
          id_token: generate_id_token(nonce: query["nonce"])
        }.to_json)
      stub_userinfo_response(email: email)

      get "/auth/result", params: { code: code, state: query["state"] }

      expect(token_stub).to have_been_requested.once
      follow_redirect!
      expect(response.body).to include(email)
    end

    it "renders the IdP error when the code_verifier is rejected" do
      query = perform_auth_request

      stub_request(:post, token_endpoint).
        to_return(status: 400, body: { error: "Code verifier code_verifier did not match code_challenge" }.to_json)

      get "/auth/result", params: { code: code, state: query["state"] }

      expect(response.body).to include("Code verifier code_verifier did not match code_challenge")
      expect(response.body).not_to include(email)
    end
  end
end
