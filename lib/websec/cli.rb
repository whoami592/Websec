# frozen_string_literal: true

module WebSec
  class CLI
    def self.start(argv)
      new(argv).run
    end

    def initialize(argv)
      @argv = argv
    end

    def run
      command = @argv.shift
      case command
      when "scan"
        scan
      when "version", "--version", "-v"
        puts "WebSec Ruby #{WebSec::VERSION}"
      else
        puts "Usage: websec scan <URL> [options]"
        puts "       websec version"
        exit(command.nil? ? 0 : 1)
      end
    end

    private

    def scan
      options = {
        format: "text",
        output: nil,
        timeout: 8,
        reflection: false
      }

      parser = OptionParser.new do |o|
        o.banner = "Usage: websec scan <URL> [options]"
        o.on("--report FORMAT", %w[text json html], "Report format") { |v| options[:format] = v }
        o.on("--output FILE", "Write report to FILE") { |v| options[:output] = v }
        o.on("--timeout SECONDS", Integer, "HTTP timeout (default 8)") { |v| options[:timeout] = v }
        o.on("--reflection", "Enable a benign query-parameter reflection check") { options[:reflection] = true }
        o.on("--no-banner", "Do not print the banner") { options[:banner] = false }
      end

      begin
        parser.parse!(@argv)
      rescue OptionParser::ParseError => e
        warn e.message
        puts parser
        exit 2
      end

      target = @argv.shift
      unless target
        puts parser
        exit 2
      end

      Banner.print unless options[:banner] == false

      begin
        scanner = Scanner.new(target, timeout: options[:timeout], reflection: options[:reflection]).run
      rescue URI::InvalidURIError, ArgumentError => e
        warn "Target error: #{e.message}"
        exit 2
      end

      puts "Target: #{target}"
      puts

      scanner.findings.each do |f|
        puts "[#{f["severity"].upcase}] #{f["id"]}: #{f["title"]}"
        puts "  Evidence: #{f["evidence"]}" if f["evidence"]
      end

      if options[:output]
        Reporter.new(scanner).write(options[:format], options[:output])
        puts
        puts "Report written to #{options[:output]}"
      end
    end
  end
end
