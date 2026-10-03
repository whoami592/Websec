# WebSec Ruby

**Web Application Security Auditor in Ruby**

Coded by **Cyber Security Engineer Mr. Sabaz Ali Khan**.

WebSec Ruby is a lightweight, defensive auditing toolkit for checking common web-application security configuration issues on systems you own or are explicitly authorized to assess.

## Features

- Security-header auditing
- Cookie flag auditing
- CORS review
- HTTP `OPTIONS` / method review
- HTTPS usage check
- Redirect review
- `robots.txt` and `security.txt` discovery
- Optional benign query-parameter reflection check
- Scope enforcement
- Request timeout controls
- JSON, text, and HTML reports
- RSpec test structure

## Requirements

- Ruby 3.0+
- Bundler

## Installation

```bash
git clone <your-repository-url>
cd ruby-websec
bundle install
chmod +x bin/websec
```

## Usage

```bash
ruby -Ilib bin/websec scan https://example.com
```

JSON report:

```bash
ruby -Ilib bin/websec scan https://example.com \
  --report json \
  --output reports/report.json
```

HTML report:

```bash
ruby -Ilib bin/websec scan https://example.com \
  --report html \
  --output reports/report.html
```

Optional reflection check:

```bash
ruby -Ilib bin/websec scan "https://example.test/search?q=test" --reflection
```

## Safety

Use this project only against applications for which you have explicit permission to test.

The default checks are intentionally non-destructive. The optional reflection check replaces existing query values with a random marker and performs a normal GET request; it does not attempt payload execution.

Do not use this tool to bypass authentication, exploit third-party systems, disrupt services, or evade security controls.

## Project structure

```text
bin/websec
lib/websec/
  banner.rb
  cli.rb
  http_client.rb
  reporter.rb
  scanner.rb
  scope.rb
  checks/
config/
reports/
spec/
```

## Severity

Severity labels are audit prioritization hints, not proof of exploitability.

- `critical` — not normally emitted by default checks
- `high` — potentially significant security configuration issue
- `medium` — meaningful weakness requiring review
- `low` — defense-in-depth issue
- `info` — informational observation

## Author

**Cyber Security Engineer Mr. Sabaz Ali Khan**

## License

MIT — see `LICENSE.md`.
