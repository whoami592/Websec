# frozen_string_literal: true
module WebSec
  module Checks
    class SecurityHeaders
      REQUIRED = {
        "content-security-policy" => ["medium", "Add a restrictive Content-Security-Policy appropriate to the application."],
        "strict-transport-security" => ["medium", "Enable HSTS after confirming HTTPS is available for the complete origin."],
        "x-content-type-options" => ["low", "Set X-Content-Type-Options: nosniff."],
        "referrer-policy" => ["low", "Set an explicit Referrer-Policy."],
        "permissions-policy" => ["low", "Set a restrictive Permissions-Policy for unused browser features."]
      }.freeze

      def initialize(scanner); @s = scanner; end
      def run
        r = @s.get
        REQUIRED.each do |header, (severity, remediation)|
          next if r[header]
          @s.finding("SecurityHeaders", "MISSING_#{header.upcase.tr("-", "_")}", severity,
                      "#{header} header is missing", remediation: remediation)
        end

        if r["server"]
          @s.finding("SecurityHeaders", "SERVER_HEADER", "info",
                      "Server header is exposed", evidence: r["server"])
        end
        if r["x-powered-by"]
          @s.finding("SecurityHeaders", "X_POWERED_BY", "low",
                      "X-Powered-By header is exposed", evidence: r["x-powered-by"],
                      remediation: "Remove framework/runtime disclosure headers where practical.")
        end
      end
    end
  end
end
