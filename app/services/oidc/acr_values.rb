# frozen_string_literal: true

module Oidc
  # Maps the UI's ial/aal selections to Login.gov acr_values URIs. Two IAL
  # vocabularies exist: the legacy idmanagement.gov URIs and the semantic
  # urn:acr.login.gov ones, toggled by semantic_ial_values_enabled.
  class AcrValues
    LEGACY_IAL_VALUES = {
      "0" => "http://idmanagement.gov/ns/assurance/ial/0",
      "1" => "http://idmanagement.gov/ns/assurance/ial/1",
      nil => "http://idmanagement.gov/ns/assurance/ial/1",
      "2" => "http://idmanagement.gov/ns/assurance/ial/2",
      "facial-match-preferred" => "http://idmanagement.gov/ns/assurance/ial/2?bio=preferred",
      "facial-match-required" => "http://idmanagement.gov/ns/assurance/ial/2?bio=required",
    }.freeze

    SEMANTIC_IAL_VALUES = {
      "0" => "http://idmanagement.gov/ns/assurance/ial/0",
      "1" => "urn:acr.login.gov:auth-only",
      nil => "urn:acr.login.gov:auth-only",
      "2" => "urn:acr.login.gov:verified",
      "facial-match-required" => "urn:acr.login.gov:verified-facial-match-required",
      "facial-match-preferred" => "urn:acr.login.gov:verified-facial-match-preferred",
    }.freeze

    AAL_VALUES = {
      "2" => "http://idmanagement.gov/ns/assurance/aal/2",
      "2-phishing_resistant" => "http://idmanagement.gov/ns/assurance/aal/2?phishing_resistant=true",
      "2-hspd12" => "http://idmanagement.gov/ns/assurance/aal/2?hspd12=true",
    }.freeze

    def self.build(ial:, aal:, config: AppConfig.instance)
      ial_values = config.semantic_ial_values_enabled? ? SEMANTIC_IAL_VALUES : LEGACY_IAL_VALUES

      [ial_values[ial], AAL_VALUES[aal]].compact.join(" ")
    end
  end
end
