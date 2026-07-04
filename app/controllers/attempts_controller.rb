# frozen_string_literal: true

class AttemptsController < ApplicationController
  def index
    @attempts_events = attempts_client.poll
  end

  def ack
    attempts_client.poll(ack: params[:jtis].split(","))

    redirect_to "/attempts-api"
  end

  private

  def attempts_client
    AttemptsApi::Client.new(config: app_config, client_id: oidc_client_id)
  end
end
