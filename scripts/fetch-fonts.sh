#!/bin/sh
# scripts/fetch-fonts.sh — download the site's webfonts for SELF-HOSTING.
#
# Run on a machine with internet access (your Mac), from the repo root:
#   sh scripts/fetch-fonts.sh
#
# It pulls the exact woff2 files Google serves for the three OFL families the
# site uses (Space Grotesk, Inter, Space Mono), writes them to web/fonts/, and
# generates web/fonts.css with the @font-face rules rewritten to local
# /fonts/… paths. After running, the site loads ZERO third-party assets — no
# request ever leaves your domain (privacy-by-design; closes the Google Fonts
# IP-transfer concern). All three fonts are licensed under the SIL Open Font
# License, so self-hosting and redistribution are permitted.
set -e

UA="Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
OUT="web/fonts"
CSS="web/fonts.css"
URL="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500&family=Space+Grotesk:wght@300;400;500;600;700&family=Space+Mono:wght@400;700&display=swap"

mkdir -p "$OUT"
echo "Fetching @font-face CSS…"
curl -fsSL -A "$UA" "$URL" -o "$CSS"

echo "Downloading woff2 files…"
n=0
for u in $(grep -oE 'https://fonts\.gstatic\.com[^)]+\.woff2' "$CSS" | sort -u); do
  f=$(basename "$u")
  curl -fsSL -A "$UA" "$u" -o "$OUT/$f"
  # rewrite this URL (every occurrence) to the local path; '#' delim avoids slash escaping
  if sed --version >/dev/null 2>&1; then sed -i "s#$u#/fonts/$f#g" "$CSS"      # GNU sed
  else sed -i '' "s#$u#/fonts/$f#g" "$CSS"; fi                                  # BSD/macOS sed
  n=$((n+1))
done

echo "Done: $n font files in $OUT, local @font-face in $CSS"
echo "Next: deploy web/fonts.css, web/fonts/, and the three .html files to the host docroot."
