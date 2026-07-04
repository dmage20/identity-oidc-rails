# frozen_string_literal: true

require "rails_helper"

RSpec.describe "GET /auth/result", type: :request do
  include_context "stubbed IdP"

  it "redirects home with access_denied when the user exits at the IdP" do
    get "/auth/result", params: { error: "access_denied" }

    expect(response).to redirect_to("/?error=access_denied")

    follow_redirect!
    expect(response.body).to include("You chose to exit before signing in")
  end

  it "renders an error when the code param is missing" do
    get "/auth/result"

    expect(response.body).to include("missing callback param: code")
  end

  it "renders the IdP error when one is present without a code" do
    get "/auth/result", params: { error: "some_error" }

    expect(response.body).to include("some_error")
  end

  it "renders an error for an invalid nonce in the id_token" do
    get "/auth/request"
    state = Rack::Utils.parse_query(URI.parse(response.location).query)["state"]

    stub_token_response(id_token: generate_id_token(nonce: "not-the-nonce"))

    get "/auth/result", params: { code: "abc123", state: state }

    expect(response.body).to include("invalid nonce")
  end

  it "renders a 500 with the IdP body when token exchange fails" do
    get "/auth/request"
    state = Rack::Utils.parse_query(URI.parse(response.location).query)["state"]

    stub_request(:post, token_endpoint).
      to_return(status: 400, body: "token exchange exploded")

    get "/auth/result", params: { code: "abc123", state: state }

    expect(response).to have_http_status(:internal_server_error)
    expect(response.body).to include("token exchange exploded")
  end

  describe "step-up continuation" do
    it "re-enters the auth flow at IAL2 with the stored AAL" do
      get "/auth/request", params: { ial: "step-up", aal: "2" }
      query = Rack::Utils.parse_query(URI.parse(response.location).query)

      stub_token_response(id_token: generate_id_token(nonce: query["nonce"]))
      stub_userinfo_response

      get "/auth/result", params: { code: "abc123", state: query["state"] }

      expect(response).to redirect_to("/auth/request?aal=2&ial=2")

      follow_redirect!
      second_query = Rack::Utils.parse_query(URI.parse(response.location).query)
      expect(second_query["acr_values"]).to eq(
        "http://idmanagement.gov/ns/assurance/ial/2 http://idmanagement.gov/ns/assurance/aal/2",
      )
    end
  end

  describe "CSP error simulation" do
    it "redirects to example.com after a successful login" do
      get "/auth/request", params: { simulate_csp: "true" }
      query = Rack::Utils.parse_query(URI.parse(response.location).query)

      stub_token_response(id_token: generate_id_token(nonce: query["nonce"]))
      stub_userinfo_response

      get "/auth/result", params: { code: "abc123", state: query["state"] }

      expect(response).to redirect_to("https://www.example.com/")
    end
  end

  describe "SSN redaction" do
    it "redacts SSN digits in the rendered userinfo" do
      get "/auth/request"
      query = Rack::Utils.parse_query(URI.parse(response.location).query)

      stub_token_response(id_token: generate_id_token(nonce: query["nonce"]))
      stub_userinfo_response(email: "test@example.com", social_security_number: "123-45-6789")

      get "/auth/result", params: { code: "abc123", state: query["state"] }
      follow_redirect!

      expect(response.body).to include("###-##-####")
      expect(response.body).not_to include("123-45-6789")
    end
  end
end
