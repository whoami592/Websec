# frozen_string_literal: true

module WebSec
  class HttpClient
    attr_reader :requests

    def initialize(timeout: 8, user_agent: "WebSec-Ruby/1.0")
      @timeout = timeout
      @user_agent = user_agent
      @requests = []
    end

    def request(uri, method: "GET", headers: {}, limit: 3)
      uri = URI.parse(uri.to_s) unless uri.is_a?(URI)
      raise ArgumentError, "Unsupported scheme" unless %w[http https].include?(uri.scheme)

      current = uri
      redirects = 0

      loop do
        response = perform(current, method, headers)
        @requests << {
          method: method,
          url: current.to_s,
          status: response.code.to_i,
          location: response["location"]
        }

        if response.is_a?(Net::HTTPRedirection) && response["location"] && redirects < limit
          next_uri = URI.join(current.to_s, response["location"])
          redirects += 1
          current = next_uri
          next
        end

        return response
      end
    end

    private

    def perform(uri, method, headers)
      http = Net::HTTP.new(uri.host, uri.port)
      http.open_timeout = @timeout
      http.read_timeout = @timeout
      http.use_ssl = uri.scheme == "https"
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER if http.use_ssl?

      klass = Net::HTTP.const_get(method.capitalize)
      request = klass.new(uri.request_uri.empty? ? "/" : uri.request_uri)
      request["User-Agent"] = @user_agent
      request["Accept"] = "*/*"
      headers.each { |k, v| request[k] = v }

      http.start { |h| h.request(request) }
    end
  end
end
