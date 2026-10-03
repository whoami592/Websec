# frozen_string_literal: true
module WebSec
  module Checks
    class Discovery
      PATHS = ["/robots.txt", "/.well-known/security.txt"].freeze
      def initialize(scanner); @s = scanner; end
      def run
        PATHS.each do |path|
          uri = @s.uri.dup
          uri.path = path
          r = @s.get(uri.to_s)
          if r.code.to_i.between?(200, 299)
            @s.finding("Discovery", "RESOURCE_#{path.gsub(/[^a-z0-9]+/i, "_")}", "info",
                        "Common resource is publicly reachable", evidence: "#{path} -> #{r.code}")
          end
        end
      end
    end
  end
end
