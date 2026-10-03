# frozen_string_literal: true
module WebSec
  module Checks
    class HttpMethods
      METHODS = %w[OPTIONS TRACE].freeze
      def initialize(scanner); @s = scanner; end
      def run
        r = @s.request_options
        if r["allow"] && r["allow"].split(",").map(&:strip).include?("TRACE")
          @s.finding("HttpMethods", "TRACE_ENABLED", "medium",
                      "TRACE appears enabled", evidence: r["allow"],
                      remediation: "Disable TRACE unless it is explicitly required.")
        end
      rescue NoMethodError
        # Use a safe GET with method override is intentionally not attempted.
        # OPTIONS is implemented directly through the client's low-risk request path below.
        uri = @s.uri
        response = @s.client.request(uri, method: "OPTIONS")
        allow = response["allow"].to_s
        if allow.split(",").map(&:strip).include?("TRACE")
          @s.finding("HttpMethods", "TRACE_ENABLED", "medium",
                      "TRACE appears enabled", evidence: allow,
                      remediation: "Disable TRACE unless explicitly required.")
        end
      end
    end
  end
end
