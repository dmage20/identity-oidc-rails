# frozen_string_literal: true

# Generous per-IP throttles: this is a public demo tool that partners hammer
# during integration testing, so limits only guard against runaway abuse.
class Rack::Attack
  LIMIT = Integer(ENV.fetch("RACK_ATTACK_LIMIT", "120"))
  PERIOD = Integer(ENV.fetch("RACK_ATTACK_PERIOD", "300"))

  throttle("auth/ip", limit: LIMIT, period: PERIOD) do |req|
    req.ip if req.path.start_with?("/auth/")
  end

  throttle("attempts/ip", limit: LIMIT, period: PERIOD) do |req|
    req.ip if req.path.start_with?("/attempts-api")
  end
end

Rack::Attack.enabled = !Rails.env.test? && ENV["RACK_ATTACK_DISABLED"] != "true"
