# frozen_string_literal: true

require "optparse"
require "uri"
require "net/http"
require "json"
require "yaml"
require "openssl"
require "time"
require "securerandom"

require_relative "websec/version"
require_relative "websec/banner"
require_relative "websec/scope"
require_relative "websec/http_client"
require_relative "websec/reporter"

require_relative "websec/checks/security_headers"
require_relative "websec/checks/cookies"
require_relative "websec/checks/cors"
require_relative "websec/checks/http_methods"
require_relative "websec/checks/tls"
require_relative "websec/checks/redirects"
require_relative "websec/checks/discovery"
require_relative "websec/checks/reflection"

require_relative "websec/scanner"
require_relative "websec/cli"
