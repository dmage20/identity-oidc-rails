# frozen_string_literal: true

require "rails_helper"

RSpec.describe "GET /", type: :request do
  include_context "stubbed IdP"

  it "pre-fills IAL2 if the URL has ?ial=2 (used in smoke tests)" do
    get "/?ial=2"

    expect(response).to have_http_status(:ok)

    doc = Nokogiri::HTML(response.body)
    ial2_option = doc.at("select[name=ial] option[value=2]")
    expect(ial2_option[:selected]).to eq "selected"
  end

  it "pre-fills HSPD12 if the URL has ?aal=2-hspd12" do
    get "/?aal=2-hspd12"

    expect(response).to have_http_status(:ok)

    doc = Nokogiri::HTML(response.body)
    aal3_option = doc.at('select[name=aal] option[value="2-hspd12"]')
    expect(aal3_option[:selected]).to eq "selected"
  end

  it "renders an error if basic auth credentials are wrong" do
    stub_request(:get, "#{host}/.well-known/openid-configuration").
      to_return(body: "", status: 401)

    get "/"

    expect(response.body).to include(
      "Perhaps we need to reimplement HTTP Basic Auth",
    )
  end

  it "renders an error if the app fails to get oidc configuration" do
    stub = stub_request(:get, "#{host}/.well-known/openid-configuration").
           to_return(body: "", status: 400)

    get "/"

    error_string = "Error: Unable to retrieve OIDC configuration from IdP. #{host} responded with 400."
    expect(response.body).to include(error_string)
    expect(stub).to have_been_requested.once
    expect(response).to have_http_status(:internal_server_error)
  end
end
