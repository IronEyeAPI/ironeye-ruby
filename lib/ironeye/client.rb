# frozen_string_literal: true

require "json"
require "logger"
require "net/http"
require "securerandom"
require "uri"

module IronEye
  # The IronEye client.
  #
  # One instance per process is the intended shape: it keeps no per-request
  # state, and Net::HTTP opens a connection per call.
  class Client
    DEFAULT_BASE_URL = "https://ironeye.org"
    RETRYABLE_STATUS = [408, 425, 429, 500, 502, 503, 504].freeze

    ANALYSIS_ROUTES = {
      analyze: "/v1/analyze",
      extract: "/v1/extract",
      classify: "/v1/classify",
      pii: "/v1/pii/analyze",
      moderation: "/v1/moderation/analyze",
      malware: "/v1/malware/scan",
      secrets: "/v1/secrets/scan",
      validate: "/v1/validate",
      deduplicate: "/v1/deduplicate",
      invoices: "/v1/invoices/parse"
    }.freeze

    DECLARATION_HEADERS = {
      legal_basis: "X-Legal-Basis",
      purpose: "X-Purpose",
      controller: "X-Controller",
      basis_evidence: "X-Basis-Evidence",
      special_condition: "X-Special-Condition",
      projection: "X-Projection"
    }.freeze

    attr_reader :base_url, :timeout, :max_retries

    # The key comes from +api_key:+ or from IRONEYE_API_KEY; the base URL from
    # +base_url:+, IRONEYE_BASE_URL, or the public host.
    def initialize(api_key: nil, base_url: nil, timeout: 60, max_retries: 2, logger: nil)
      @api_key = api_key || ENV["IRONEYE_API_KEY"]
      raise ArgumentError, "An API key is required: pass api_key: or set IRONEYE_API_KEY." if @api_key.to_s.empty?

      @base_url = (base_url || ENV["IRONEYE_BASE_URL"] || DEFAULT_BASE_URL).sub(%r{/+\z}, "")
      @timeout = timeout
      @max_retries = max_retries
      @logger = logger || Logger.new(File::NULL)
    end

    # -- analysis ------------------------------------------------------------
    ANALYSIS_ROUTES.each do |name, path|
      define_method(name) do |payload, idempotency_key: nil|
        headers = idempotency_key ? { "Idempotency-Key" => idempotency_key } : {}
        send(:request, :post, path, body: payload, headers: headers)
      end
    end

    # Multipart, for bytes you hold already rather than base64 in a body.
    def analyze_upload(file, filename: "document", content_type: "application/octet-stream",
                       features: nil, preset: nil, options: nil, output_mode: nil,
                       retention_seconds: nil, idempotency_key: nil)
      fields = {
        "features" => features&.join(","),
        "preset" => preset,
        "options" => (JSON.generate(options) if options),
        "output_mode" => output_mode,
        "retention_seconds" => retention_seconds&.to_s
      }.compact
      boundary = "ironeye-#{SecureRandom.hex(16)}"
      headers = { "Content-Type" => "multipart/form-data; boundary=#{boundary}" }
      headers["Idempotency-Key"] = idempotency_key if idempotency_key
      request(:post, "/v1/analyze/upload",
              raw: multipart(boundary, file, filename, content_type, fields),
              headers: headers)
    end

    # -- jobs ----------------------------------------------------------------
    def create_job(payload) = request(:post, "/v1/jobs", body: payload)
    def job(job_id) = request(:get, "/v1/jobs/#{escape(job_id)}")
    def delete_job(job_id) = request(:delete, "/v1/jobs/#{escape(job_id)}")

    # Polls until the job settles. Nothing in the service dispatches to a
    # callback URL, so polling is the whole asynchronous contract.
    def await_job(job_id, interval: 2, timeout: 300)
      deadline = monotonic + timeout
      loop do
        record = job(job_id)
        return record if %w[completed failed].include?(record["status"])
        raise Error, "Job #{job_id} was still #{record["status"]} after #{timeout}s." if monotonic + interval > deadline

        sleep(interval)
      end
    end

    # -- collection ----------------------------------------------------------
    def catalogue = request(:get, "/v1/harvest/catalogue")
    def operations(platform = nil) = request(:get, "/v1/harvest/operations", query: { platform: platform }.compact)
    def operation(op_id) = request(:get, "/v1/harvest/operations/#{escape(op_id)}")

    # Runs one operation, addressed by its own route as the catalogue gives it:
    # "/v1/harvest/reddit/subreddit", say.
    def collect(path, params = {}, declaration = {})
      request(:get, path, query: params, headers: declaration_headers(declaration))
    end

    # +collect+ for the operations the registry declares as POST. The parameters
    # are identical; only where they travel changes.
    def collect_post(path, params = {}, declaration = {})
      request(:post, path, body: params, headers: declaration_headers(declaration))
    end

    # -- data subject rights -------------------------------------------------
    def gdpr_notice = request(:get, "/v1/gdpr/notice")
    def erasure(subject) = request(:post, "/v1/gdpr/erasure", body: subject)
    def objection(subject) = request(:post, "/v1/gdpr/objections", body: subject)
    def access_request(subject) = request(:post, "/v1/gdpr/access", body: subject)
    def suppression = request(:get, "/v1/gdpr/suppression")
    def unsuppress(subject_key) = request(:delete, "/v1/gdpr/suppression/#{escape(subject_key)}")

    # -- service -------------------------------------------------------------
    def health = request(:get, "/healthz")
    def ready = request(:get, "/readyz")
    def features = request(:get, "/v1/features")
    def status = request(:get, "/v1/status")
    def audit_head = request(:get, "/v1/audit/head")

    def inspect = "#<IronEye::Client base_url=#{@base_url.inspect} key=#{masked_key.inspect}>"

    def to_s = "#{inspect} # everything is an object; the key is not one you get"

    private

    def request(method, path, query: {}, body: nil, raw: nil, headers: {})
      uri = URI.parse(@base_url + path)
      uri.query = URI.encode_www_form(query) unless query.nil? || query.empty?
      attempt = 0
      begin
        started = monotonic
        response = dispatch(method, uri, body, raw, headers)
        interpret(response, method, path, monotonic - started)
      rescue APIError => e
        raise unless retry?(e, attempt)

        wait(attempt, response, e.code, path)
        attempt += 1
        retry
      rescue *NETWORK_ERRORS => e
        raise ConnectionError, "#{method.upcase} #{path} failed: #{e.message}" if attempt >= @max_retries

        wait(attempt, nil, "CONNECTION", path)
        attempt += 1
        retry
      end
    end

    NETWORK_ERRORS = [
      Errno::ECONNREFUSED, Errno::ECONNRESET, Errno::EHOSTUNREACH, IOError,
      Net::OpenTimeout, Net::ReadTimeout, SocketError
    ].freeze
    private_constant :NETWORK_ERRORS

    def dispatch(method, uri, body, raw, headers)
      klass = { get: Net::HTTP::Get, post: Net::HTTP::Post, delete: Net::HTTP::Delete }.fetch(method)
      http_request = klass.new(uri)
      http_request["Accept"] = "application/json"
      http_request["Authorization"] = "Bearer #{@api_key}"
      http_request["User-Agent"] = "ironeye-ruby/#{IronEye::VERSION}"
      headers.each { |name, value| http_request[name] = value }
      if raw
        http_request.body = raw
      elsif body
        http_request["Content-Type"] = "application/json"
        http_request.body = JSON.generate(body)
      end

      Net::HTTP.start(uri.hostname, uri.port,
                      use_ssl: uri.scheme == "https",
                      open_timeout: @timeout,
                      read_timeout: @timeout) { |http| http.request(http_request) }
    end

    def interpret(response, method, path, elapsed)
      status = response.code.to_i
      @logger.debug do
        format("ironeye %<method>s %<path>s -> %<status>d in %<ms>dms (request_id=%<id>s)",
               method: method.to_s.upcase, path: path, status: status,
               ms: elapsed * 1000, id: response["x-request-id"] || "-")
      end
      return nil if [204, 205].include?(status)

      payload = parse(response.body)
      return payload if status < 400

      raise IronEye.error_from(status, payload)
    end

    def parse(body)
      return nil if body.nil? || body.empty?

      JSON.parse(body)
    rescue JSON::ParserError
      { "error" => { "code" => "INTERNAL", "message" => body[0, 200] } }
    end

    def retry?(error, attempt)
      attempt < @max_retries && error.retryable? && RETRYABLE_STATUS.include?(error.status)
    end

    # Retry-After is the server's own number, so it wins over the curve.
    def wait(attempt, response, code, path)
      advised = response && response["retry-after"].to_s
      seconds = advised.to_s.match?(/\A\d+\z/) ? advised.to_i : (0.25 * (2**attempt)) + rand * 0.25
      @logger.warn { format("ironeye %<path>s retrying after %<code>s in %<ms>dms", path: path, code: code, ms: seconds * 1000) }
      sleep(seconds)
    end

    def declaration_headers(declaration)
      declaration.each_with_object({}) do |(key, value), out|
        name = DECLARATION_HEADERS[key.to_sym]
        out[name] = value.to_s if name && value
      end
    end

    def multipart(boundary, file, filename, content_type, fields)
      parts = fields.map do |name, value|
        "--#{boundary}\r\nContent-Disposition: form-data; name=\"#{name}\"\r\n\r\n#{value}\r\n"
      end
      parts << "--#{boundary}\r\nContent-Disposition: form-data; name=\"file\"; " \
               "filename=\"#{filename}\"\r\nContent-Type: #{content_type}\r\n\r\n"
      "#{parts.join}#{file}\r\n--#{boundary}--\r\n".b
    end

    def escape(value) = URI.encode_www_form_component(value.to_s)

    # Enough of the key to recognise it in a log, never enough to use it.
    def masked_key = @api_key.length > 12 ? "#{@api_key[0, 9]}..." : "..."

    def monotonic = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end
end
