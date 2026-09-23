Aegis | Web Inspector

Aegis is a full-stack Python web application engineered for real-time domain inspection, security header compliance auditing, technology stack fingerprinting, and client-side network telemetry. Built with Streamlit, Requests, and BeautifulSoup, the application evaluates target web architecture against modern security standards and OWASP recommendations.
Key Features
🌐 Dynamic Target Fingerprinting & Hero Telemetry

    Automated Icon & Metadata Extraction: Pulls high-resolution favicon assets, raw page title metadata, and hostname data upon target initiation.

    Sliding Glassmorphism UI: Displays real-time DOM status via CSS keyframe-animated cards with neon styling and responsive layout blocks.

    Client Connection Telemetry: Analyzes the client's public IP footprint, ISP, geographic location, and proxy/VPN status to flag potential Deep Packet Inspection (DPI) and DNS interception risks.

⚙️ Infrastructure & Tech Stack Detection

    Server & CDN Fingerprinting: Inspects response headers to identify underlying server infrastructure (Nginx, Apache) and CDN networks (Cloudflare).

    Framework & CMS Discovery: Scans script tags, DOM attributes, and header signatures to detect active frameworks (React, Next.js, Vue.js, Express, PHP) and CMS installations (WordPress, Shopify).

    WHOIS Domain Registration Tracking: Performs raw socket queries to pull creation dates, age in years, and domain registrar details.

🔒 Cryptographic & OWASP Security Audits

    Direct Socket SSL/TLS Inspection: Establishes direct SSL socket handshakes with target port 443 to extract certificate authorities, expiration dates, and remaining validity periods.

    OWASP Security Header Compliance: Scores target web applications against critical security headers:

        Strict-Transport-Security (HSTS)

        Content-Security-Policy (CSP)

        X-Frame-Options

        X-Content-Type-Options

        Referrer-Policy

        Permissions-Policy

🕵️ Telemetry, Tracking & Topology Scanning

    Third-Party Script Analysis: Scans embedded scripts and external sources for commercial tracking and telemetry engines (Google Analytics, GTM, Facebook Pixel, Hotjar, Microsoft Clarity, Mixpanel, Segment, TikTok Pixel, Datadog/Sentry).

    Link Topology Audit: Calculates internal versus external hyperlink ratios.

    Reverse Tabnabbing Vulnerability Check: Identifies unsafe external links using target="_blank" without explicit rel="noopener" or rel="noreferrer" attributes.

🎨 SEO, OpenGraph & Automated Reporting

    Metadata & Social Previews: Scrapes standard HTML title tags, meta descriptions, and OpenGraph (og:title, og:image) tags to generate social media card previews.

    JSON Audit Export: Encapsulates complete diagnostic payloads—including WHOIS data, SSL metrics, headers, stack components, and topology—into a single downloadable JSON report.

Tech Stack & Dependencies

    Language: Python 3.9+

    Interface Engine: Streamlit

    HTTP Client & Parsing: Requests, BeautifulSoup4

    Domain & Network Intelligence: python-whois, socket, ssl

Installation & Setup

    Clone the Repository
    Bash

    git clone https://github.com/your-username/aegis-web-inspector.git
    cd aegis-web-inspector

    Install Required Packages
    Bash

    pip install streamlit requests beautifulsoup4 python-whois

    Run the Application
    Bash

    python -m streamlit run app.py

