# frozen_string_literal: true

# Single factory for outbound HTTP so every request to the IdP gets TLS
# verification, timeouts, and consistent failure logging.
class FaradayConnection
  OPEN_TIMEOUT = 5
  TIMEOUT = 10

  def self.build(url:, params: nil, headers: nil)
    Faraday.new(url: url, params: params, headers: headers, ssl: { verify: true }) do |f|
      f.request :url_encoded
      f.options.open_timeout = OPEN_TIMEOUT
      f.options.timeout = TIMEOUT
    end
  end

  def self.get(url)
    build(url: url).get
  end

  def self.post(url, body = nil)
    build(url: url).post(nil, body)
  end

  def self.log_failure(response, url)
    return if response.status == 200

    Rails.logger.warn("got #{response.status} trying to query #{url}")
  end
end
