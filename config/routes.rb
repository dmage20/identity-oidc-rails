Rails.application.routes.draw do
  root "home#index"

  get "/auth/request", to: "auth#request_authorization"
  get "/auth/result", to: "auth#result"

  get "/failure_to_proof", to: "home#failure_to_proof"

  post "/handle-logout", to: "sessions#destroy"
  get "/logout", to: "sessions#logged_out"

  get "/attempts-api", to: "attempts#index"
  post "/ack-events", to: "attempts#ack"

  namespace :api do
    get "health", to: "health#show"
  end

  # Rails' built-in liveness check (in addition to /api/health parity endpoint)
  get "up" => "rails/health#show", as: :rails_health_check
end
