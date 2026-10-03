# frozen_string_literal: true

module WebSec
  class Reporter
    def initialize(scanner)
      @scanner = scanner
    end

    def data
      counts = Hash.new(0)
      @scanner.findings.each { |f| counts[f["severity"]] += 1 }

      {
        "tool" => "WebSec Ruby",
        "version" => WebSec::VERSION,
        "author" => "Cyber Security Engineer Mr. Sabaz Ali Khan",
        "target" => @scanner.target,
        "generated_at" => Time.now.utc.iso8601,
        "summary" => counts,
        "findings" => @scanner.findings
      }
    end

    def write(format, output)
      case format
      when "json"
        File.write(output, JSON.pretty_generate(data))
      when "text"
        File.write(output, text)
      when "html"
        File.write(output, html)
      else
        raise ArgumentError, "Unsupported report format: #{format}"
      end
    end

    def text
      lines = []
      lines << "WebSec Ruby Report"
      lines << "Target: #{@scanner.target}"
      lines << "Generated: #{data["generated_at"]}"
      lines << ""
      @scanner.findings.each do |f|
        lines << "[#{f["severity"].upcase}] #{f["id"]}: #{f["title"]}"
        lines << "  Evidence: #{f["evidence"]}" if f["evidence"]
        lines << "  Remediation: #{f["remediation"]}" if f["remediation"]
      end
      lines.join("\n") + "\n"
    end

    def html
      rows = @scanner.findings.map do |f|
        "<tr><td>#{esc(f["severity"])}</td><td>#{esc(f["id"])}</td><td>#{esc(f["title"])}</td><td>#{esc(f["evidence"].to_s)}</td><td>#{esc(f["remediation"].to_s)}</td></tr>"
      end.join
      <<~HTML
        <!doctype html><html><head><meta charset="utf-8">
        <title>WebSec Ruby Report</title>
        <style>body{font-family:system-ui;margin:2rem}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:.5rem;text-align:left}</style>
        </head><body><h1>WebSec Ruby Report</h1>
        <p><b>Target:</b> #{esc(@scanner.target)}</p>
        <table><tr><th>Severity</th><th>ID</th><th>Finding</th><th>Evidence</th><th>Remediation</th></tr>#{rows}</table>
        </body></html>
      HTML
    end

    private

    def esc(value)
      value.to_s.gsub("&", "&amp;").gsub("<", "&lt;").gsub(">", "&gt;").gsub('"', "&quot;")
    end
  end
end
