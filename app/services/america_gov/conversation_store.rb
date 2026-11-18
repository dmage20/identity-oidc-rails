# frozen_string_literal: true

require "fileutils"

module AmericaGov
  # File-backed JSON store for zero-knowledge encrypted conversations and client-side tickets.
  # The server never receives or persists plaintext message content.
  class ConversationStore
    DEFAULT_PATH = Rails.root.join("tmp", "america_gov_conversations.json")
    ALLOWED_FIELDS = %w[id user_sub source kind epk iv aad ciphertext created_at].freeze

    def initialize(path: DEFAULT_PATH)
      @path = Pathname.new(path)
      @mutex = Mutex.new
    end

    def list(user_sub)
      @mutex.synchronize do
        read_all.fetch(user_sub.to_s, [])
      end
    end

    def append(user_sub:, record:)
      sanitized = sanitize_record(user_sub:, record:)
      @mutex.synchronize do
        data = read_all
        data[user_sub.to_s] ||= []
        data[user_sub.to_s] << sanitized
        write_all(data)
      end
      sanitized
    end

    def clear(user_sub)
      @mutex.synchronize do
        data = read_all
        data.delete(user_sub.to_s)
        write_all(data)
      end
    end

    def raw_json_for(user_sub)
      JSON.pretty_generate(list(user_sub))
    end

    private

    def sanitize_record(user_sub:, record:)
      item = record.stringify_keys.slice("kind", "source", "epk", "iv", "aad", "ciphertext")
      {
        "id" => SecureRandom.uuid,
        "user_sub" => user_sub.to_s,
        "source" => item["source"].presence || "browser",
        "kind" => item["kind"].presence || "chat",
        "epk" => item.fetch("epk"),
        "iv" => item.fetch("iv"),
        "aad" => item.fetch("aad"),
        "ciphertext" => item.fetch("ciphertext"),
        "created_at" => Time.now.utc.iso8601
      }.slice(*ALLOWED_FIELDS)
    end

    def read_all
      return {} unless @path.exist?

      content = @path.read
      content.blank? ? {} : JSON.parse(content)
    rescue JSON::ParserError
      {}
    end

    def write_all(data)
      FileUtils.mkdir_p(@path.dirname)
      @path.write(JSON.pretty_generate(data))
    end
  end
end
