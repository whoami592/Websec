# frozen_string_literal: true
module WebSec
  class Scanner
    def reflection_probe
      marker = "websec_reflection_#{SecureRandom.hex(6)}"
      uri = @scope.base_uri.dup
      params = URI.decode_www_form(uri.query.to_s)
      return unless params.any?
      params = params.map { |k, v| [k, marker] }
      uri.query = URI.encode_www_form(params)
      response = get(uri.to_s)
      if response.body.to_s.include?(marker)
        finding("Reflection", "REFLECTED_INPUT", "medium",
                "A query parameter value was reflected in the response",
                evidence: "Marker #{marker} was reflected",
                remediation: "Contextually encode untrusted output and validate input. Reflection alone does not prove XSS.")
      end
    end
  end
end

module WebSec
  module Checks
    class Reflection
      def initialize(scanner); @s = scanner; end
      def run
        @s.reflection_probe
      end
    end
  end
end
