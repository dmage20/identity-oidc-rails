# frozen_string_literal: true

require "rails_helper"

RSpec.describe "GET /auth/request", type: :request do
  include_context "stubbed IdP"

  def request_query(params = {})
    get "/auth/request", params: params
    expect(response).to have_http_status(:redirect)
    Rack::Utils.parse_query(URI.parse(response.location).query)
  end

  describe "IAL variants (legacy acr_values)" do
    it "defaults to IAL1" do
      query = request_query
      expect(query["acr_values"]).to eq("http://idmanagement.gov/ns/assurance/ial/1")
    end

    it "sends IAL2 when ial=2" do
      query = request_query(ial: "2")
      expect(query["acr_values"]).to eq("http://idmanagement.gov/ns/assurance/ial/2")
    end

    it "sends IAL0 (IALMax) when ial=0" do
      query = request_query(ial: "0")
      expect(query["acr_values"]).to eq("http://idmanagement.gov/ns/assurance/ial/0")
    end

    it "sends bio=preferred for facial-match-preferred" do
      query = request_query(ial: "facial-match-preferred")
      expect(query["acr_values"]).to eq("http://idmanagement.gov/ns/assurance/ial/2?bio=preferred")
    end

    it "sends bio=required for facial-match-required" do
      query = request_query(ial: "facial-match-required")
      expect(query["acr_values"]).to eq("http://idmanagement.gov/ns/assurance/ial/2?bio=required")
    end
  end

  describe "semantic acr_values" do
    before { ENV["semantic_ial_values_enabled"] = "true" }
    after { ENV["semantic_ial_values_enabled"] = "false" }

    it "sends urn:acr.login.gov:auth-only for IAL1" do
      query = request_query(ial: "1")
      expect(query["acr_values"]).to eq("urn:acr.login.gov:auth-only")
    end

    it "sends urn:acr.login.gov:verified for IAL2" do
      query = request_query(ial: "2")
      expect(query["acr_values"]).to eq("urn:acr.login.gov:verified")
    end

    it "sends verified-facial-match-required" do
      query = request_query(ial: "facial-match-required")
      expect(query["acr_values"]).to eq("urn:acr.login.gov:verified-facial-match-required")
    end
  end

  describe "AAL values" do
    it "appends AAL2" do
      query = request_query(ial: "1", aal: "2")
      expect(query["acr_values"]).to eq(
        "http://idmanagement.gov/ns/assurance/ial/1 http://idmanagement.gov/ns/assurance/aal/2",
      )
    end

    it "appends phishing-resistant AAL2" do
      query = request_query(ial: "1", aal: "2-phishing_resistant")
      expect(query["acr_values"]).to include("aal/2?phishing_resistant=true")
    end

    it "appends HSPD12 AAL2" do
      query = request_query(ial: "1", aal: "2-hspd12")
      expect(query["acr_values"]).to include("aal/2?hspd12=true")
    end
  end

  describe "PKCE" do
    before { ENV["PKCE"] = "true" }
    after { ENV["PKCE"] = "false" }

    it "sends the PKCE client id, code_challenge, and S256 method" do
      query = request_query

      expect(query["client_id"]).to eq("urn:gov:gsa:openidconnect:sp:sinatra_pkce")
      expect(query["code_challenge"]).to be_present
      expect(query["code_challenge_method"]).to eq("S256")
    end
  end

  describe "prompt parameter" do
    it "sends prompt=select_account by default" do
      query = request_query
      expect(query["prompt"]).to eq("select_account")
    end

    it "sends prompt=create when initiate_registration is checked" do
      query = request_query(initiate_registration: "true")
      expect(query["prompt"]).to eq("create")
    end
  end

  describe "step-up flow" do
    it "requests IAL1 when ial=step-up" do
      query = request_query(ial: "step-up", aal: "2")
      expect(query["acr_values"]).to include("ial/1")
    end
  end

  describe "enhanced in-person proofing" do
    it "hides the eipp option unless enabled" do
      get "/"
      doc = Nokogiri::HTML(response.body)
      expect(doc.at("select[name=ial] option[value=enhanced-ipp-required]")).to be_nil
    end

    it "shows the eipp option when enabled" do
      ENV["eipp_allowed"] = "true"
      AppConfig.reset!

      get "/"
      doc = Nokogiri::HTML(response.body)
      expect(doc.at("select[name=ial] option[value=enhanced-ipp-required]")).to be_present
    ensure
      ENV.delete("eipp_allowed")
    end
  end
end
