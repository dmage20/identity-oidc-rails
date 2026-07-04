# frozen_string_literal: true

module Oidc
  # The scope options offered in the UI and the defaults pre-selected for
  # each IAL choice. https://developers.login.gov/attributes/
  class Scopes
    ALL = %w[
      sub
      email
      all_emails
      locale
      ial
      aal
      profile
      given_name
      family_name
      address
      phone
      birthdate
      social_security_number
      verified_at
      x509
      x509_issuer
      x509_subject
      x509_presented
    ].freeze

    IAL2_OPTIONS = %w[
      2
      facial-match-preferred
      facial-match-required
      enhanced-ipp-required
    ].freeze

    IAL2_DEFAULT_SCOPES = %w[
      openid
      email
      profile
      social_security_number
      phone
      address
      x509
    ].freeze

    def self.default_scopes_by_ial
      defaults = {
        nil => %w[openid email x509],
        "0" => %w[openid email social_security_number x509],
        "1" => %w[openid email x509],
      }

      IAL2_OPTIONS.each { |ial| defaults[ial] = IAL2_DEFAULT_SCOPES }

      defaults
    end
  end
end
