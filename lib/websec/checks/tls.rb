# frozen_string_literal: true
module WebSec
  module Checks
    class Tls
      def initialize(scanner); @s = scanner; end
      def run
        if @s.uri.scheme == "https"
          @s.finding("Tls", "HTTPS_ENABLED", "info", "Target uses HTTPS")
        else
          @s.finding("Tls", "HTTP_ONLY", "high", "Target is using plain HTTP",
                      remediation: "Serve sensitive application traffic exclusively over HTTPS and redirect HTTP safely.")
        end
      end
    end
  end
end
