# frozen_string_literal: true

module WebSec
  class Scope
    def initialize(target)
      @uri = URI.parse(target)
      raise ArgumentError, "Target must use HTTP or HTTPS" unless %w[http https].include?(@uri.scheme)
      raise ArgumentError, "Target must contain a hostname" if @uri.host.nil? || @uri.host.empty?
    end

    def allowed?(url)
      other = URI.parse(url)
      other.scheme == @uri.scheme && other.host == @uri.host && effective_port(other) == effective_port(@uri)
    rescue URI::InvalidURIError
      false
    end

    def base_uri
      @uri
    end

    private

    def effective_port(uri)
      uri.port
    end
  end
end
