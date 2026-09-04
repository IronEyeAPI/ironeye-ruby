# frozen_string_literal: true

module IronEye
  # Base of every error this gem raises.
  class Error < StandardError; end

  # An error the server described in its response body.
  #
  # +retryable+ is the server's own verdict rather than an inference from the
  # status code: a 429 from a spent monthly allowance is not the same wait as a
  # 429 from a rate limiter, and only the body tells them apart.
  class APIError < Error
    attr_reader :status, :code, :retryable, :request_id, :suggested_action, :doc, :path, :meta

    def initialize(status, body)
      @status = status
      @code = body["code"] || "INTERNAL"
      @retryable = body.fetch("retryable", false)
      @request_id = body["request_id"] || "-"
      @suggested_action = body["suggested_action"].to_s
      @doc = body["doc"].to_s
      @path = body["path"]
      @meta = body["meta"] || {}
      super("#{@code}: #{body["message"]} (request_id=#{@request_id})")
    end

    alias retryable? retryable
  end

  class AuthenticationError < APIError; end
  class PermissionError < APIError; end
  class RateLimitError < APIError; end
  class InvalidRequestError < APIError; end
  class NotFoundError < APIError; end
  class ComplianceError < APIError; end
  class UpstreamError < APIError; end
  class ServerError < APIError; end

  # A transport failure, where there is no server verdict to read.
  class ConnectionError < Error
    def retryable? = true
  end

  FAMILIES = {
    "UNAUTHENTICATED" => AuthenticationError,
    "FORBIDDEN_SCOPE" => PermissionError,
    "PLAN_LIMITED" => PermissionError,
    "RATE_LIMITED" => RateLimitError,
    "QUOTA_EXHAUSTED" => RateLimitError,
    "TENANT_BUSY" => RateLimitError,
    "NOT_FOUND" => NotFoundError,
    "COMPLIANCE_REFUSED" => ComplianceError,
    "COLLECTION_BLOCKED" => ComplianceError,
    "SOURCE_NOT_CONFIGURED" => UpstreamError,
    "UPSTREAM_REFUSED" => UpstreamError,
    "UPSTREAM_THROTTLED" => UpstreamError,
    "INTERNAL" => ServerError,
    "DEPENDENCY_UNAVAILABLE" => ServerError,
    "SERVER_DRAINING" => ServerError
  }.freeze
  private_constant :FAMILIES

  # Builds the narrowest error class the response body justifies.
  def self.error_from(status, payload)
    body = payload.is_a?(Hash) ? payload["error"] : nil
    unless body.is_a?(Hash) && body["code"]
      return ServerError.new(status, {
                               "code" => "INTERNAL",
                               "message" => "The server returned #{status} with no error body.",
                               "retryable" => status >= 500,
                               "suggested_action" => "Retry, and quote the status if it persists."
                             })
    end
    FAMILIES.fetch(body["code"], InvalidRequestError).new(status, body)
  end
end
