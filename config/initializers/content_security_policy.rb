# Be sure to restart your server when you modify this file.

# Enforced CSP. All redirects to the IdP are 302s, so form_action :self holds;
# the scopes-by-IAL payload is a <script type="application/json"> data block,
# which is not executable and passes script_src.
Rails.application.configure do
  config.content_security_policy do |policy|
    policy.default_src :self
    policy.script_src  :self
    policy.style_src   :self
    policy.img_src     :self, :data
    policy.font_src    :self
    policy.connect_src :self
    policy.form_action :self
    policy.frame_ancestors :none
    policy.base_uri    :self
    policy.object_src  :none
  end
end
