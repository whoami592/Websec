require "spec_helper"

RSpec.describe WebSec::Reporter do
  it "produces structured report data" do
    scanner = instance_double(WebSec::Scanner,
      target: "https://example.com",
      findings: [{"severity" => "info", "id" => "TEST", "title" => "Test"}])
    data = described_class.new(scanner).data
    expect(data["tool"]).to eq("WebSec Ruby")
    expect(data["summary"]["info"]).to eq(1)
  end
end
