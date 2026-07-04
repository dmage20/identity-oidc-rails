# frozen_string_literal: true

# Step-up flow: the user first authenticates at IAL1, then is immediately
# sent back through authorization at IAL2 with the AAL they chose up front.
module StepUpFlow
  extend ActiveSupport::Concern

  private

  def prepare_step_up_flow(ial:, aal: nil)
    if ial == "step-up"
      ial = "1"
      session[:step_up_enabled] = "true"
      session[:step_up_aal] = aal if /^\d$/.match?(aal)
    else
      session.delete(:step_up_enabled)
      session.delete(:step_up_aal)
    end

    ial
  end
end
