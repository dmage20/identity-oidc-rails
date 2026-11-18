# frozen_string_literal: true

module AmericaGov
  # Seals an offline server-generated case summary to the user's P-256 public site key.
  # Once sealed, the ephemeral private key is discarded so America.gov's server cannot decrypt it.
  class ServerSealer
    CURVE = "prime256v1"
    ALG_INFO = "A256GCM"

    def self.seal(payload, public_jwk:, user_sub:)
      new(public_jwk:, user_sub:).seal(payload)
    end

    def initialize(public_jwk:, user_sub:)
      @public_jwk = public_jwk.stringify_keys
      @user_sub = user_sub.to_s
    end

    def seal(payload)
      recipient_key = JWT::JWK.import(@public_jwk.transform_keys(&:to_sym)).verify_key
      ephemeral = OpenSSL::PKey::EC.generate(CURVE)
      epk_jwk = JWT::JWK.new(ephemeral).export.slice(:kty, :crv, :x, :y).stringify_keys

      shared_secret = ephemeral.dh_compute_key(recipient_key.public_key)
      key = derive_key(shared_secret)

      aad_str = Base64.urlsafe_encode64(epk_jwk.to_json, padding: false)
      cipher = OpenSSL::Cipher.new("aes-256-gcm").encrypt
      cipher.key = key
      iv = cipher.random_iv
      cipher.auth_data = aad_str
      ciphertext = cipher.update(payload.to_json) + cipher.final
      combined_ciphertext = ciphertext + cipher.auth_tag

      {
        "source" => "server_sealed",
        "kind" => "offline_case_summary",
        "epk" => epk_jwk,
        "iv" => Base64.urlsafe_encode64(iv, padding: false),
        "aad" => aad_str,
        "ciphertext" => Base64.urlsafe_encode64(combined_ciphertext, padding: false)
      }
    end

    private

    def derive_key(shared_secret)
      OpenSSL::Digest::SHA256.digest(
        [ 1 ].pack("N") +
          shared_secret +
          [ @user_sub.bytesize ].pack("N") +
          @user_sub +
          ALG_INFO,
      )
    end
  end
end
