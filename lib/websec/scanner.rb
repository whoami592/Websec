# frozen_string_literal: true

module WebSec
  class Scanner
    CHECKS = [
      WebSec::Checks::SecurityHeaders,
      WebSec::Checks::Cookies,
      WebSec::Checks::Cors,
      WebSec::Checks::HttpMethods,
      WebSec::Checks::Tls,
      WebSec::Checks::Redirects,
      WebSec::Checks::Discovery,
      WebSec::Checks::Reflection
    ].freeze

    attr_reader :target, :findings

    def initialize(target, timeout: 8, reflection: false)
      @target = target
      @scope = Scope.new(target)
      @client = HttpClient.new(timeout: timeout)
      @findings = []
      @reflection = reflection
    end

    def run
      CHECKS.each do |check|
        next if check == WebSec::Checks::Reflection && !@reflection
        begin
          check.new(self).run
        rescue StandardError => e
          @findings << finding(
            check.name.split("::").last,
            "CHECK_ERROR",
            "info",
            "Check failed safely: #{e.class}: #{e.message}"
          )
        end
      end
      self
    end

    def get(url = @target, headers: {})
      raise SecurityError, "URL is outside target scope" unless @scope.allowed?(url)
      @client.request(url, headers: headers)
    end

    def head(url = @target, headers: {})
      raise SecurityError, "URL is outside target scope" unless @scope.allowed?(url)
      @client.request(url, method: "HEAD", headers: headers)
    end

    def uri
      @scope.base_uri
    end

    def request_options
      @client.request(@scope.base_uri, method: "OPTIONS")
    end

    def client
      @client
    end

    def finding(check, id, severity, title, evidence: nil, remediation: nil)
      item = {
        "check" => check,
        "id" => id,
        "severity" => severity,
        "title" => title
      }
      item["evidence"] = evidence if evidence
      item["remediation"] = remediation if remediation
      @findings << item
      item
    end
  end
end
