# frozen_string_literal: true

require_relative "lib/websec/version"

Gem::Specification.new do |spec|
  spec.name          = "websec-ruby"
  spec.version       = WebSec::VERSION
  spec.authors       = ["Mr. Sabaz Ali Khan"]
  spec.summary       = "Authorized web application security auditing toolkit"
  spec.description   = "A defensive Ruby toolkit for web security configuration auditing."
  spec.homepage      = "https://github.com/"
  spec.license       = "MIT"
  spec.files         = Dir["bin/**/*", "lib/**/*", "spec/**/*", "*.md", "Gemfile", "Rakefile", "*.gemspec"]
  spec.bindir        = "bin"
  spec.executables   = ["websec"]
  spec.require_paths = ["lib"]
  spec.required_ruby_version = ">= 3.0"
end
