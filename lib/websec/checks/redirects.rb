# frozen_string_literal: true
module WebSec
  module Checks
    class Redirects
      def initialize(scanner); @s = scanner; end
      def run
        return unless @s.uri.scheme == "http"
        r = @s.get
        location = r["location"]
        return unless location

        target = URI.join(@s.target, location).to_s
        unless @s.send(:instance_variable_get, :@scope).allowed?(target)
          @s.finding("Redirects", "CROSS_ORIGIN_REDIRECT", "medium",
                      "Initial request redirects outside the target origin",
                      evidence: target,
                      remediation: "Review redirects and avoid unexpected cross-origin redirects.")
        end
      end
    end
  end
end
