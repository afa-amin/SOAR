#!/bin/sh
read -r input

echo "[$(date)] DEBUG - Raw Input: $input" >> /var/ossec/logs/active-responses.log

json_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g'
}

URL=$(echo "$input" | grep -oE '"url"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n1 | cut -d'"' -f4)

if [ -z "$URL" ]; then
    URL=$(echo "$input" | grep -oE '"uri"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n1 | cut -d'"' -f4)
fi

if [ -z "$URL" ]; then
    URL=$(echo "$input" | grep -oE '"request"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n1 | cut -d'"' -f4)
fi

if [ -z "$URL" ]; then
    URL=$(echo "$input" | grep -oE 'https?://[^"[:space:]\\]+' | head -n1)
fi

SRC_IP=$(echo "$input" | grep -oE '"srcip"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n1 | cut -d'"' -f4)
[ -z "$SRC_IP" ] && SRC_IP=$(echo "$input" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)

RULE_ID=$(echo "$input" | grep -oE '"rule"[[:space:]]*:[[:space:]]*\{[^}]*"id"[[:space:]]*:[[:space:]]*"?[0-9]+"?' | grep -oE '[0-9]+' | tail -n1)
RULE_DESC=$(echo "$input" | grep -oE '"description"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n1 | cut -d'"' -f4)

echo "[$(date)] DEBUG - Extracted URL: $URL | SrcIP: $SRC_IP | Rule: $RULE_ID | Desc: $RULE_DESC" >> /var/ossec/logs/active-responses.log

if [ -z "$URL" ]; then
    echo "[$(date)] ERROR - No URL found in alert input" >> /var/ossec/logs/active-responses.log
    exit 1
fi

URL_ESC=$(json_escape "$URL")
IP_ESC=$(json_escape "$SRC_IP")
DESC_ESC=$(json_escape "$RULE_DESC")

SHUFFLE_WEBHOOK_URL="https://shuffler.io/api/v1/hooks/SECRET"

curl -s --max-time 15 -X POST "$SHUFFLE_WEBHOOK_URL" \
     -H "Content-Type: application/json" \
     -d "{\"url\":\"$URL_ESC\",\"src_ip\":\"$IP_ESC\",\"rule_id\":\"$RULE_ID\",\"description\":\"$DESC_ESC\",\"time\":\"$(date '+%Y-%m-%d %H:%M:%S')\"}" > /dev/null

echo "[$(date)] Sent URL to Shuffle webhook - URL: $URL | Rule: $RULE_ID" >> /var/ossec/logs/active-responses.log
