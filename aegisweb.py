import datetime
import json
import re
import socket
import ssl
import time
import urllib.parse
from bs4 import BeautifulSoup
import requests
import streamlit as st
import whois


# To run code, use: python -m streamlit run web.py | if the previous command didnt work, try: streamlit run web.py


# 1. Page Config & Animated Glassmorphic CSS

st.set_page_config(
    page_title="Aegis",
    page_icon="🌌",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    /* Dark Theme Core */
    .stApp {
        background-color: #05070E;
        color: #F3F4F6;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    /* Hide Default UI Artifacts */
    header {visibility: hidden;}
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}

    /* Keyframe Animations */
    @keyframes slideDownFade {
        0% { transform: translateY(-30px) scale(0.97); opacity: 0; }
        100% { transform: translateY(0) scale(1); opacity: 1; }
    }
    @keyframes pulseGlow {
        0% { box-shadow: 0 0 15px rgba(56, 189, 248, 0.15); }
        50% { box-shadow: 0 0 25px rgba(56, 189, 248, 0.35); }
        100% { box-shadow: 0 0 15px rgba(56, 189, 248, 0.15); }
    }
    @keyframes cardFadeIn {
        from { opacity: 0; transform: translateY(12px); }
        to { opacity: 1; transform: translateY(0); }
    }

    /* Target Dynamic Header Banner */
    .target-header-card {
        animation: slideDownFade 0.7s cubic-bezier(0.16, 1, 0.3, 1) forwards, pulseGlow 4s infinite;
        background: linear-gradient(135deg, rgba(17, 24, 39, 0.85), rgba(9, 13, 22, 0.95));
        border: 1px solid rgba(56, 189, 248, 0.3);
        border-radius: 20px;
        padding: 24px 32px;
        display: flex;
        align-items: center;
        gap: 24px;
        margin-bottom: 2rem;
        backdrop-filter: blur(16px);
    }
    .target-icon {
        width: 72px;
        height: 72px;
        border-radius: 16px;
        object-fit: contain;
        background: #111827;
        border: 1px solid rgba(255, 255, 255, 0.1);
        padding: 6px;
        box-shadow: 0 8px 20px rgba(0, 0, 0, 0.4);
    }
    .target-title {
        font-size: 2.4rem;
        font-weight: 800;
        margin: 0;
        background: linear-gradient(90deg, #38BDF8, #A78BFA, #34D399);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        line-height: 1.2;
    }
    .target-url {
        font-size: 1rem;
        color: #9CA3AF;
        margin-top: 4px;
        font-family: monospace;
    }

    /* Glassmorphism Metric Cards */
    .glass-card {
        background: rgba(17, 24, 39, 0.6);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 16px;
        padding: 20px;
        margin-bottom: 16px;
        backdrop-filter: blur(12px);
        animation: cardFadeIn 0.5s ease-out forwards;
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .glass-card:hover {
        border-color: rgba(56, 189, 248, 0.4);
        transform: translateY(-2px);
    }
    .card-label {
        font-size: 0.75rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #9CA3AF;
        margin-bottom: 6px;
    }
    .card-value {
        font-size: 1.8rem;
        font-weight: 800;
        color: #F9FAFB;
    }

    /* Tech Stack Pills */
    .tech-pill {
        display: inline-block;
        padding: 6px 14px;
        background: rgba(167, 139, 250, 0.12);
        border: 1px solid rgba(167, 139, 250, 0.35);
        color: #C4B5FD;
        border-radius: 20px;
        font-weight: 600;
        margin: 4px;
        font-size: 0.85rem;
    }
    </style>
""",
    unsafe_allow_html=True,
)

# 2. Core Intelligence Modules

def extract_hostname(url: str) -> str:
  parsed = urllib.parse.urlparse(url)
  netloc = parsed.netloc or parsed.path
  return netloc.split(":")[0].replace("www.", "")


def get_favicon_url(hostname: str) -> str:
  clean_host = hostname.replace("www.", "")
  return f"https://t3.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=http://{clean_host}&size=128"


def get_user_network_telemetry():
  try:
    res = requests.get("https://ipapi.co/json/", timeout=4).json()
    return {
        "ip": res.get("ip", "Unknown"),
        "isp": res.get("org", "Unknown"),
        "city": res.get("city", "Unknown"),
        "country": res.get("country_name", "Unknown"),
        "vpn": res.get("in_eu", False),
    }
  except Exception:
    return {
        "ip": "Unknown",
        "isp": "Unknown",
        "city": "Unknown",
        "country": "Unknown",
        "vpn": False,
    }


def analyze_ssl_certificate(hostname: str):
  try:
    context = ssl.create_default_context()
    with socket.create_connection((hostname, 443), timeout=5) as sock:
      with context.wrap_socket(sock, server_hostname=hostname) as ssock:
        cert = ssock.getpeercert()
        expire_date = datetime.datetime.strptime(
            cert.get("notAfter"), "%b %d %H:%M:%S %Y %Z"
        )
        days_remaining = (expire_date - datetime.datetime.utcnow()).days
        issuer_info = dict(x[0] for x in cert.get("issuer", []))
        issuer_org = issuer_info.get(
            "organizationName", issuer_info.get("commonName", "Verified CA")
        )

        return {
            "status": "Valid",
            "issuer": issuer_org,
            "expires": expire_date.strftime("%B %d, %Y"),
            "days_left": days_remaining,
        }
  except Exception as e:
    return {"status": "Invalid / Missing", "error": str(e), "days_left": 0}


def analyze_security_headers(headers: dict):
  required_headers = {
      "Strict-Transport-Security": "HSTS Enforced",
      "Content-Security-Policy": "CSP Enforced",
      "X-Frame-Options": "Clickjacking Protection",
      "X-Content-Type-Options": "MIME Sniffing Protection",
      "Referrer-Policy": "Referrer Policy Defined",
      "Permissions-Policy": "Permissions Policy Configured",
  }
  present, missing = {}, {}

  for header, label in required_headers.items():
    match = next(
        (v for k, v in headers.items() if k.lower() == header.lower()), None
    )
    if match:
      present[header] = match
    else:
      missing[header] = label

  score = int((len(present) / len(required_headers)) * 100)
  return {"score": score, "present": present, "missing": missing}


def get_domain_whois(hostname: str):
  try:
    w = whois.whois(hostname)
    creation_date = w.creation_date
    if isinstance(creation_date, list):
      creation_date = creation_date[0]

    if creation_date and isinstance(creation_date, datetime.datetime):
      age_years = (datetime.datetime.now() - creation_date).days // 365
      return {
          "created": creation_date.strftime("%B %d, %Y"),
          "age": f"{age_years} years",
          "registrar": w.registrar or "Unknown",
      }
    return {
        "created": "Protected / Unlisted",
        "age": "N/A",
        "registrar": "Unknown",
    }
  except Exception:
    return {
        "created": "Protected / Unlisted",
        "age": "N/A",
        "registrar": "Unknown",
    }


def detect_tech_stack(headers: dict, soup: BeautifulSoup):
  stack = []
  server = headers.get("Server", "").lower()
  if "cloudflare" in server:
    stack.append("Cloudflare CDN")
  if "nginx" in server:
    stack.append("Nginx Server")
  if "apache" in server:
    stack.append("Apache Server")

  x_powered = headers.get("X-Powered-By", "").lower()
  if "php" in x_powered:
    stack.append("PHP")
  if "express" in x_powered:
    stack.append("Express.js")

  html_text = str(soup).lower()
  if "wp-content" in html_text or soup.find(
      "meta", attrs={"name": "generator", "content": re.compile("WordPress", re.I)}
  ):
    stack.append("WordPress")
  if "id=\"__next\"" in html_text or "_next/static" in html_text:
    stack.append("Next.js (React)")
  elif "id=\"root\"" in html_text and "react" in html_text:
    stack.append("React.js")
  if "data-v-" in html_text:
    stack.append("Vue.js")
  if "cdn.shopify.com" in html_text:
    stack.append("Shopify")

  return list(set(stack)) if stack else ["Custom / Obfuscated Stack"]


def detect_trackers_and_scripts(soup: BeautifulSoup):
  tracker_signatures = {
      "Google Analytics": r"google-analytics\.com|ga\.js|analytics\.js",
      "Google Tag Manager": r"googletagmanager\.com",
      "Facebook Pixel": r"connect\.facebook\.net",
      "Hotjar": r"static\.hotjar\.com",
      "Microsoft Clarity": r"clarity\.ms",
      "Mixpanel": r"cdn\.mxpnl\.com",
      "Segment": r"cdn\.segment\.com",
      "TikTok Pixel": r"analytics\.tiktok\.com",
      "Datadog / Sentry": r"browser-http-intake\.datadoghq|sentry\.io",
  }
  found = set()
  scripts = [s.get("src", "") for s in soup.find_all("script") if s.get("src")]
  inline_scripts = "".join(
      [s.string for s in soup.find_all("script") if s.string]
  )

  for name, pattern in tracker_signatures.items():
    if any(re.search(pattern, src, re.I) for src in scripts) or re.search(
        pattern, inline_scripts, re.I
    ):
      found.add(name)

  return list(found)


def analyze_links_and_security(soup: BeautifulSoup, base_url: str):
  base_domain = extract_hostname(base_url)
  links = soup.find_all("a", href=True)
  internal, external, unsafe_external = 0, 0, 0

  for link in links:
    href = link["href"]
    parsed_href = urllib.parse.urlparse(href)

    if not parsed_href.netloc or base_domain in parsed_href.netloc:
      internal += 1
    else:
      external += 1
      target = link.get("target", "").lower()
      rel = link.get("rel", [])
      rel_str = " ".join(rel) if isinstance(rel, list) else str(rel)

      if (
          target == "_blank"
          and "noopener" not in rel_str
          and "noreferrer" not in rel_str
      ):
        unsafe_external += 1

  return {
      "total": len(links),
      "internal": internal,
      "external": external,
      "unsafe_external": unsafe_external,
  }



# Sidebar 

st.sidebar.markdown(
    "<h2 style='color:#38BDF8; font-weight:1200; margin-top:0;'>Aegis"
    "</h2>",
    unsafe_allow_html=True,
)
st.sidebar.caption("Aegis | Site Inspector")

url_input = st.sidebar.text_input(
    "Target Domain / URL", placeholder="example.com"
)
analyze_btn = st.sidebar.button(
    "RUN DEEP DIAGNOSTIC", type="primary", use_container_width=True
)

st.sidebar.divider()
st.sidebar.markdown("### Client Network Security")
net_info = get_user_network_telemetry()
st.sidebar.markdown(f"**IP:** `{net_info['ip']}`")
st.sidebar.markdown(f"**Location:** {net_info['city']}, {net_info['country']}")
st.sidebar.markdown(f"**ISP:** {net_info['isp']}")

if net_info["vpn"]:
  st.sidebar.warning("⚠️ **Proxy / Hosting Node Active**")
  st.sidebar.caption(
      "DPI Warning: Firewalls can still inspect SNI headers and DNS requests"
      " despite proxy usage."
  )
else:
  st.sidebar.success("✅ **Direct Residential ISP Connection**")



# Engine

if not url_input and not analyze_btn:
  st.markdown(
      """
        <div style="text-align: center; margin-top: 18vh; animation: cardFadeIn 0.8s ease-out;">
            <h1 style="font-size: 3.5rem; background: linear-gradient(90deg, #475569, #94A3B8); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">Awaiting Diagnostic Target.</h1>
            <p style="color: #64748B; font-size: 1.1rem; max-width: 600px; margin: 0 auto;">Input a target URL in the sidebar terminal to initialize WHOIS, SSL certificate chains, OWASP header audits, and tracker discovery.</p>
        </div>
    """,
      unsafe_allow_html=True,
  )
  st.stop()

if analyze_btn or url_input:
  if not url_input.startswith(("http://", "https://")):
    url_input = "https://" + url_input

  hostname = extract_hostname(url_input)

  with st.spinner(f"Initiating multi-layer diagnostic scan on {hostname}..."):
    try:
      start_time = time.time()
      headers = {
          "User-Agent": (
              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
              " (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
          )
      }
      res = requests.get(
          url_input, headers=headers, timeout=10, allow_redirects=True
      )
      ttfb = round((time.time() - start_time) * 1000)

      soup = BeautifulSoup(res.text, "html.parser")
      site_title = (
          soup.title.string.strip() if soup.title else hostname.capitalize()
      )
      favicon_url = get_favicon_url(hostname)

      # Slide Animations
      st.markdown(
          f"""
                <div class="target-header-card">
                    <img src="{favicon_url}" class="target-icon" onerror="this.src='https://cdn-icons-png.flaticon.com/512/3214/3214736.png'"/>
                    <div>
                        <h1 class="target-title">{site_title[:50]}{'...' if len(site_title) > 50 else ''}</h1>
                        <div class="target-url">🌐 {url_input}</div>
                    </div>
                </div>
            """,
          unsafe_allow_html=True,
      )

      # Compute Metrics
      whois_data = get_domain_whois(hostname)
      ssl_data = analyze_ssl_certificate(hostname)
      sec_headers = analyze_security_headers(res.headers)
      trackers = detect_trackers_and_scripts(soup)
      stack = detect_tech_stack(res.headers, soup)
      link_metrics = analyze_links_and_security(soup, url_input)
      page_size_kb = round(len(res.content) / 1024, 1)

      # Top Metric Cards Grid
      c1, c2, c3, c4, c5 = st.columns(5)
      with c1:
        st.markdown(
            f"""<div class="glass-card">
            <div class="card-label">HTTP Status</div>
            <div class="card-value" style="color:{'#34D399' if res.status_code == 200 else '#FB7185'}">{res.status_code}</div>
        </div>""",
            unsafe_allow_html=True,
        )
      with c2:
        st.markdown(
            f"""<div class="glass-card">
            <div class="card-label">Latency (TTFB)</div>
            <div class="card-value" style="color:#38BDF8">{ttfb} <span style="font-size:0.9rem">ms</span></div>
        </div>""",
            unsafe_allow_html=True,
        )
      with c3:
        st.markdown(
            f"""<div class="glass-card">
            <div class="card-label">Security Score</div>
            <div class="card-value" style="color:#A78BFA">{sec_headers['score']}%</div>
        </div>""",
            unsafe_allow_html=True,
        )
      with c4:
        st.markdown(
            f"""<div class="glass-card">
            <div class="card-label">Domain Age</div>
            <div class="card-value" style="color:#FBBF24">{whois_data['age']}</div>
        </div>""",
            unsafe_allow_html=True,
        )
      with c5:
        st.markdown(
            f"""<div class="glass-card">
            <div class="card-label">SSL Validity</div>
            <div class="card-value" style="color:{'#34D399' if ssl_data['days_left'] > 0 else '#FB7185'}">{ssl_data['days_left']} <span style="font-size:0.9rem">days</span></div>
        </div>""",
            unsafe_allow_html=True,
        )

      # Diagnostics Tab
      tab1, tab2, tab3, tab4, tab5 = st.tabs([
          "⚙️ Infrastructure & Stack",
          "🔒 Security Headers & SSL",
          "🕵️ Telemetry & Trackers",
          "🎨 SEO & Social Cards",
          "💾 Export JSON Report",
      ])

      # Tab 1: Tech Stack
      with tab1:
        st.markdown("### Detected Infrastructure & Software")
        pills_html = " ".join(
            [f"<span class='tech-pill'>{t}</span>" for t in stack]
        )
        st.markdown(
            f"<div style='margin-bottom:20px;'>{pills_html}</div>",
            unsafe_allow_html=True,
        )

        sc1, sc2 = st.columns(2)
        with sc1:
          st.write(f"**Domain Registration Date:** `{whois_data['created']}`")
          st.write(f"**Registrar:** `{whois_data['registrar']}`")
        with sc2:
          st.write(f"**Payload Size:** `{page_size_kb} KB`")
          st.write(f"**Encoding:** `{res.encoding}`")

        st.markdown("#### Server Response Headers")
        st.json(dict(res.headers), expanded=False)

      # Tab 2: OWASP SECURITY & SSL
      with tab2:
        st.markdown("### SSL/TLS Certificate Analysis")
        if ssl_data["status"] == "Valid":
          st.success(
              f"**Valid Certificate Authority:** {ssl_data['issuer']} | Expiration:"
              f" {ssl_data['expires']}"
          )
        else:
          st.error(f"SSL Failure: {ssl_data.get('error')}")

        st.divider()
        st.markdown("### OWASP Security Header Compliance")
        col_pres, col_miss = st.columns(2)

        with col_pres:
          st.markdown("#### ✅ Active Hardening Headers")
          if sec_headers["present"]:
            for h, v in sec_headers["present"].items():
              st.success(f"**{h}**\n\n`{v}`")
          else:
            st.info("No standard security headers detected.")

        with col_miss:
          st.markdown("#### ❌ Missing Recommended Protection")
          if sec_headers["missing"]:
            for h, desc in sec_headers["missing"].items():
              st.error(f"**{h}** — {desc}")

      # Tab 3: Trackers & Links
      with tab3:
        st.markdown("### Scraped Third-Party Telemetry & Trackers")
        if trackers:
          st.warning(
              f"⚠️ Discovered {len(trackers)} active user tracking scripts on"
              " this page."
          )
          for tr in trackers:
            st.markdown(f"- 🚩 **{tr}**")
        else:
          st.success(
              "✅ Clean — No standard commercial tracking scripts detected."
          )

        st.divider()
        st.markdown("### Link Topology & Tabnabbing Vulnerabilities")
        lc1, lc2, lc3, lc4 = st.columns(4)
        lc1.metric("Total Links", link_metrics["total"])
        lc2.metric("Internal Links", link_metrics["internal"])
        lc3.metric("External Links", link_metrics["external"])
        lc4.metric(
            "Unsafe Links",
            link_metrics["unsafe_external"],
            delta="Tabnabbing Risk"
            if link_metrics["unsafe_external"]
            else "Secure",
            delta_color="inverse",
        )

        if link_metrics["unsafe_external"] > 0:
          st.warning(
              f"⚠️ **Vulnerability Warning:** {link_metrics['unsafe_external']}"
              " external links open in a new tab without `rel='noopener'` or"
              " `rel='noreferrer'`, exposing users to reverse tabnabbing"
              " phishing attacks."
          )

      # Tab 4: SEO & OPENGRAPH
      with tab4:
        st.markdown("### SEO & Metadata")
        meta_desc = soup.find("meta", attrs={"name": "description"})
        st.write(
            f"**Page Title:** `{soup.title.string if soup.title else 'Missing'}`"
        )
        st.write(
            "**Meta Description:**"
            f" `{meta_desc.get('content') if meta_desc else 'Missing'}`"
        )

        st.divider()
        st.markdown("### OpenGraph Social Card Preview")
        og_title = soup.find("meta", property="og:title")
        og_image = soup.find("meta", property="og:image")

        og1, og2 = st.columns(2)
        with og1:
          st.write(
              "**og:title:**"
              f" `{og_title.get('content') if og_title else 'Not Configured'}`"
          )
          st.write(
              "**og:image:**"
              f" `{og_image.get('content') if og_image else 'Not Configured'}`"
          )
        with og2:
          if og_image and og_image.get("content"):
            st.image(
                og_image.get("content"),
                caption="Social Card Preview",
                use_container_width=True,
            )

      # Tab 5: .json Export
      with tab5:
        st.markdown("### Download Full JSON Security Audit")
        audit_payload = {
            "target": url_input,
            "timestamp": str(datetime.datetime.now()),
            "status_code": res.status_code,
            "latency_ms": ttfb,
            "domain_whois": whois_data,
            "ssl_security": ssl_data,
            "security_headers": sec_headers,
            "tech_stack": stack,
            "trackers_found": trackers,
            "link_topology": link_metrics,
        }
        st.download_button(
            label="📥 Download Audit Payload (JSON)",
            file_name=f"audit_{hostname}_{datetime.date.today()}.json",
            mime="application/json",
            data=json.dumps(audit_payload, indent=2),
        )

    except Exception as general_err:
      st.markdown(
          f"""
            <div style="background: rgba(251, 113, 133, 0.1); border: 1px solid #FB7185; padding: 20px; border-radius: 12px; color: #FB7185;">
                <h3>⚠️ Diagnostic Failure</h3>
                <p>Unable to establish connection or execute audit on target.</p>
                <code>Error Details: {str(general_err)}</code>
            </div>
        """,
          unsafe_allow_html=True,
      ) 