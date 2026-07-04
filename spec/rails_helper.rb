# This file is copied to spec/ when you run 'rails generate rspec:install'
require 'spec_helper'
ENV['RAILS_ENV'] ||= 'test'
require_relative '../config/environment'
# Prevent database truncation if the environment is production
abort("The Rails environment is running in production mode!") if Rails.env.production?
require 'rspec/rails'
require 'webmock/rspec'
require 'nokogiri'

Rails.root.glob('spec/support/**/*.rb').sort_by(&:to_s).each { |f| require f }

module FixtureHelpers
  def read_fixture_file(file)
    File.read(Rails.root.join('spec/fixtures', file))
  end
end

RSpec.configure do |config|
  config.use_active_record = false

  config.include FixtureHelpers

  # AppConfig memoizes env-derived values (including the SP private key);
  # reset around every example so ENV stubs take effect.
  config.before do
    AppConfig.reset!
    Rails.cache.clear
  end

  # Filter lines from Rails gems in backtraces.
  config.filter_rails_from_backtrace!
end
