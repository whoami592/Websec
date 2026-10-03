require "spec_helper"

RSpec.describe WebSec::Scope do
  it "allows only the same origin" do
    scope = described_class.new("https://example.com/app")
    expect(scope.allowed?("https://example.com/test")).to eq(true)
    expect(scope.allowed?("https://evil.example/test")).to eq(false)
  end

  it "rejects unsupported schemes" do
    expect { described_class.new("ftp://example.com") }.to raise_error(ArgumentError)
  end
end
