# BurpJS Collector

A Burp Suite extension that passively collects JavaScript files from in-scope targets during browsing.

## Features

- **Passive collection** — captures all JS responses as you browse
- **Inline script extraction** — pulls `<script>` blocks from HTML responses (where apps like Facebook, Google, and Microsoft embed most of their logic)
- **Content-hash deduplication** — skips files with identical MD5 even if served from different URLs (common with CDN versioning)
- **Organized export** — separates external and inline scripts into folders, preserves URL path structure

## Installation

1. Make sure Jython is configured in Burp Suite: **Extender → Options → Python Environment** → set the Jython JAR path
2. Go to **Extender → Extensions → Add**
3. Set Extension Type to **Python**
4. Select `js_collector.py`
5. The **JS Collector** tab will appear in Burp

## Usage

1. Add your target to scope: **Target → Scope → Add**
2. Browse the target website normally through Burp's proxy
3. The extension automatically captures all JS files and inline scripts
4. Check the **JS Collector v2** tab to see what's been collected
5. Set your export folder path and click **Export All JS Files**


## Searching Exported Files

The export includes a `search.sh` helper:

```bash
# Make it executable
chmod +x search.sh

# Search for DOM XSS sinks
./search.sh innerHTML
./search.sh "document.write"
./search.sh eval

# Search for postMessage handlers
./search.sh postMessage
./search.sh addEventListener

# Search for redirect sinks
./search.sh "location.href"
./search.sh "window.open"

# Search for API keys and secrets
./search.sh "api_key"
./search.sh "secret"
```

Or use grep directly:

```bash
# Find all postMessage listeners with context
grep -rn --include="*.js" -B2 -A5 "addEventListener.*message" burp_js_export/

# Find potential open redirects
grep -rn --include="*.js" "location\.href\s*=" burp_js_export/

# Find hardcoded tokens
grep -rn --include="*.js" -iE "(api.?key|secret|token|password)\s*[:=]" burp_js_export/
```

### Recommended: Beautify Before Searching

The built-in beautifier is basic. For heavily minified code, run js-beautify after export:

```bash
npm install -g js-beautify
find burp_js_export/ -name "*.js" -exec js-beautify -r {} \;
```
