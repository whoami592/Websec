# frozen_string_literal: true
module WebSec
  module Checks
    class Cookies
      def initialize(scanner); @s = scanner; end
      def run
        r = @s.get
        cookies = r.get_fields("set-cookie") || []
        cookies.each_with_index do |cookie, i|
          low = cookie.downcase
          unless low.include?("secure")
            @s.finding("Cookies", "COOKIE_NO_SECURE_#{i}", "medium",
                        "Cookie lacks the Secure attribute", evidence: cookie,
                        remediation: "Mark sensitive cookies Secure so they are only sent over HTTPS.")
          end
          unless low.include?("httponly")
            @s.finding("Cookies", "COOKIE_NO_HTTPONLY_#{i}", "medium",
                        "Cookie lacks the HttpOnly attribute", evidence: cookie,
                        remediation: "Use HttpOnly for cookies that do not need JavaScript access.")
          end
          unless low.include?("samesite")
            @s.finding("Cookies", "COOKIE_NO_SAMESITE_#{i}", "low",
                        "Cookie does not declare SameSite", evidence: cookie,
                        remediation: "Set an explicit SameSite policy appropriate to the application.")
          end
        end
      end
    end
  end
end
