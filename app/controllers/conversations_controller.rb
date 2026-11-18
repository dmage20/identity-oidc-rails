# frozen_string_literal: true

class ConversationsController < ApplicationController
  before_action :require_authenticated_user

  def index
    user_sub = session[:user_sub]
    render json: {
      user_sub: user_sub,
      items: store.list(user_sub),
      raw_store_json: store.raw_json_for(user_sub)
    }
  end

  def create
    record = params.require(:conversation).permit(
      :kind,
      :source,
      :iv,
      :aad,
      :ciphertext,
      epk: %i[kty crv x y],
    ).to_h

    saved = store.append(user_sub: session[:user_sub], record: record)
    render json: {
      item: saved,
      raw_store_json: store.raw_json_for(session[:user_sub])
    }, status: :created
  end

  def create_server_sealed
    public_jwk = session[:site_key_public]
    if public_jwk.blank?
      return render json: { error: "No site_key_public in session yet" }, status: :unprocessable_entity
    end

    ticket = {
      kind: "offline_case_summary",
      sender: "America.gov Async Benefits Processor (Server-Sealed)",
      title: "Case Summary Ticket ##{rand(10_000..99_999)}",
      body: "Automated SSA eligibility & fraud-prevention summary sealed at #{Time.now.utc.strftime('%H:%M:%S UTC')}. " \
            "Encrypted using your public site key; the server discarded the ephemeral key immediately.",
      timestamp: Time.now.utc.iso8601
    }

    sealed = AmericaGov::ServerSealer.seal(ticket, public_jwk: public_jwk, user_sub: session[:user_sub])
    saved = store.append(user_sub: session[:user_sub], record: sealed)

    render json: {
      item: saved,
      raw_store_json: store.raw_json_for(session[:user_sub])
    }, status: :created
  end

  def destroy
    store.clear(session[:user_sub])
    render json: { items: [], raw_store_json: "[]" }
  end

  private

  def require_authenticated_user
    return if session[:user_sub].present?

    render json: { error: "Unauthorized" }, status: :unauthorized
  end

  def store
    @store ||= AmericaGov::ConversationStore.new
  end
end
