# frozen_string_literal: true

require "rails_helper"

RSpec.describe "POST /handle-logout", type: :request do
  include_context "stubbed IdP"

  it "clears the session and redirects to the IdP logout endpoint" do
    # Log in first so the session has user state to clear.
    get "/auth/request", params: { ial: "step-up", aal: "2" }
    query = Rack::Utils.parse_query(URI.parse(response.location).query)
    stub_token_response(id_token: generate_id_token(nonce: query["nonce"]))
    stub_userinfo_response(email: "user@example.com")
    get "/auth/result", params: { code: "abc", state: query["state"] }

    post "/handle-logout"

    expect(session[:userinfo]).to be_nil
    expect(session[:email]).to be_nil
    expect(session[:step_up_enabled]).to be_nil
    expect(session[:step_up_aal]).to be_nil
    expect(session[:irs]).to be_nil

    expect(response.location).to include(end_session_endpoint)

    logout_query = Rack::Utils.parse_query(URI.parse(response.location).query)
    expect(logout_query["client_id"]).to eq(client_id)
    expect(logout_query["post_logout_redirect_uri"]).to eq("http://localhost:9292/logout")
  end

  it "shows the logged-out banner after the IdP redirects back" do
    get "/logout"

    expect(response).to redirect_to("/")
    follow_redirect!
    expect(response.body).to include("You have been logged out.")
  end
end
