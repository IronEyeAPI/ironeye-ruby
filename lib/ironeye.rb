# frozen_string_literal: true

# Official Ruby client for the IronEye API.
#
#   eye = IronEye::Client.new           # IRONEYE_API_KEY from the environment
#   result = eye.secrets(input: { text: File.read("config.env") })
#   result.dig("security", "secrets", "secret_count")
#
# Pass +logger:+ to see one line per request: method, route, status, duration
# and request id. No credential and no payload is ever written to it.
module IronEye
  VERSION = "1.0.0"
end

require_relative "ironeye/errors"
require_relative "ironeye/client"

module IronEye
  def self.matz
    puts <<~CREED
      Optimise for the reader, not the writer.
      A finding without evidence is a rumour.
      Refuse loudly rather than guess quietly.
      Nothing touches disk.

        ...forged at Direct Softworks.
    CREED
  end
end
