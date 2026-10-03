# frozen_string_literal: true
module WebSec
  module Checks
    class Cors
      def initialize(scanner); @s = scanner; end
      def run
        r = @s.get(headers: {"Origin" => "https://websec-audit.invalid"})
        origin = r["access-control-allow-origin"]
        credentials = r["access-control-allow-credentials"]

        return unless origin

        @s.finding("Cors", "CORS_PRESENT", "info",
                    "CORS policy is present", evidence: "Access-Control-Allow-Origin: #{origin}")

        if origin == "*"
          severity = credentials.to_s.downcase == "true" ? "high" : "medium"
          @s.finding("Cors", "CORS_WILDCARD", severity,
                      "CORS allows every origin", evidence: origin,
                      remediation: "Prefer an explicit allowlist of trusted origins for sensitive resources.")
        end
      end
    end
  end
end
