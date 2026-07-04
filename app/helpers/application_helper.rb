# frozen_string_literal: true

module ApplicationHelper
  def ial_select_options
    options = [
      [ "1", "Authentication only (default)" ],
      [ "2", "Identity-verified" ],
      [ "0", "IALMax" ],
      [ "step-up", "Step-up Flow" ],
      [ "facial-match-preferred", "Facial Match Preferred (ACR)" ],
      [ "facial-match-required", "Facial Match Required (ACR)" ]
    ]

    if AppConfig.instance.eipp_allowed?
      options << [
        "enhanced-ipp-required", "Enhanced In-Person Proofing (Enabled in dev & staging only)"
      ]
    end

    options
  end

  def scope_options
    Oidc::Scopes::ALL
  end

  def default_scopes_by_ial
    Oidc::Scopes.default_scopes_by_ial
  end

  def maybe_redact_ssn(ssn)
    if AppConfig.instance.redact_ssn?
      # redact all characters since they're all sensitive
      ssn = ssn&.gsub(/\d/, "#")
    end

    ssn
  end
end
