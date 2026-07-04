# frozen_string_literal: true

module AttemptsHelper
  def event_data(event_values)
    AttemptsApi::Redactor.new(config: AppConfig.instance).event_data(event_values)
  end
end
