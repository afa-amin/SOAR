#!/bin/sh
read -r input

json_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g'
}

send_bale() {
    TEXT_ESCAPED=$(json_escape "$1")
    curl -s --max-time 15 -X POST "https://tapi.bale.ai/79017824:PuxKTVU9WvpGz6sQDk42siuIt65DdVZOzd8/sendMessage" \
         -H "Content-Type: application/json" \
         -d "{\"chat_id\":\"896298845\",\"text\":\"$TEXT_ESCAPED\"}" > /dev/null
}

FILE=$(echo "$input" | grep -o '"path":[^,}]*' | cut -d'"' -f4 | sed 's/.*\///')
FULL_PATH=$(echo "$input" | grep -o '"path":[^,}]*' | cut -d'"' -f4)
[ -z "$FILE" ] && FILE="Unknown file"

echo "[$(date)] DEBUG - FILE: $FILE" >> /var/ossec/logs/active-responses.log
echo "[$(date)] DEBUG - FULL_PATH: $FULL_PATH" >> /var/ossec/logs/active-responses.log

if [ ! -f "$FULL_PATH" ]; then
    send_bale "❌ File not found: $FULL_PATH"
    exit 1
fi

VT_API_KEY="a112ca042d3e6a78124faffdb6b81ae04be6bf6011958d8df6de2109323d9ccd"

send_bale "🆕 New File Added !\nFile: $FILE\nTime: $(date '+%Y-%m-%d %H:%M:%S')"

VT_RESPONSE=$(curl -s --connect-timeout 10 --max-time 60 -w "\n%{http_code}" --request POST \
     --url https://www.virustotal.com/api/v3/files \
     --header "x-apikey: $VT_API_KEY" \
     --form "file=@$FULL_PATH" 2>>/var/ossec/logs/active-responses.log)

HTTP_CODE=$(echo "$VT_RESPONSE" | tail -n1)
VT_BODY=$(echo "$VT_RESPONSE" | sed '$d')

echo "[$(date)] DEBUG - HTTP Code: $HTTP_CODE" >> /var/ossec/logs/active-responses.log
echo "[$(date)] DEBUG - VT Response: $VT_BODY" >> /var/ossec/logs/active-responses.log

if [ "$HTTP_CODE" != "200" ]; then
    ERROR_CODE=$(echo "$VT_BODY" | grep -oE '"code"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | cut -d'"' -f4)
    ERROR_MSG=$(echo "$VT_BODY" | grep -oE '"message"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | cut -d'"' -f4)
    [ -z "$ERROR_CODE" ] && ERROR_CODE="Unknown"
    [ -z "$ERROR_MSG" ] && ERROR_MSG="See server log (active-responses.log) for full response"
    send_bale "❌ VirusTotal Upload Failed!\nFile: $FILE\nHTTP: $HTTP_CODE\nCode: $ERROR_CODE\nMessage: $ERROR_MSG"
    exit 1
fi

ANALYSIS_ID=$(echo "$VT_BODY" | grep -oE '"id"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n1 | cut -d'"' -f4)

if [ -z "$ANALYSIS_ID" ]; then
    send_bale "❌ No Analysis ID from VirusTotal\nFile: $FILE"
    exit 1
fi

SCAN_TEXT="🔍 VirusTotal Scan Started!\nFile: $FILE\n\n📋 Full Analysis ID:\n$ANALYSIS_ID\n\n🔗 Link:\nhttps://www.virustotal.com/gui/file/$ANALYSIS_ID"
send_bale "$SCAN_TEXT"

echo "[$(date)] Scan started - $FILE | ID: $ANALYSIS_ID - waiting for completion..." >> /var/ossec/logs/active-responses.log


echo "[$(date)] Scan started - $FILE | ID: $ANALYSIS_ID - waiting for completion..." >> /var/ossec/logs/active-responses.log

MAX_RETRIES=30
RETRY_COUNT=0
SCAN_COMPLETE=0
STATUS_RESULT=""

while [ $RETRY_COUNT -lt $MAX_RETRIES ] && [ $SCAN_COMPLETE -eq 0 ]; do
    sleep 5
    RETRY_COUNT=$((RETRY_COUNT + 1))

    STATUS_RESPONSE=$(curl -s --connect-timeout 10 --max-time 20 --request GET \
        --url "https://www.virustotal.com/api/v3/analyses/$ANALYSIS_ID" \
        --header "x-apikey: $VT_API_KEY")

    STATUS=$(echo "$STATUS_RESPONSE" | grep -oE '"status"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | cut -d'"' -f4)

    echo "[$(date)] DEBUG - Poll #$RETRY_COUNT - Status: $STATUS" >> /var/ossec/logs/active-responses.log

    if [ "$STATUS" = "completed" ]; then
        SCAN_COMPLETE=1
        STATUS_RESULT="$STATUS_RESPONSE"
    fi
done

if [ $SCAN_COMPLETE -eq 0 ]; then
    send_bale "⏰ Scan Still Processing After Timeout!\nFile: $FILE\n\n🆔 Analysis ID:\n$ANALYSIS_ID\n\n🔗 Check manually:\nhttps://www.virustotal.com/gui/file/$ANALYSIS_ID"
    echo "[$(date)] Timeout waiting for scan - $FILE | ID: $ANALYSIS_ID" >> /var/ossec/logs/active-responses.log
    exit 1
fi

echo "[$(date)] Scan completed - $FILE | ID: $ANALYSIS_ID" >> /var/ossec/logs/active-responses.log

HARMLESS=$(echo "$STATUS_RESULT" | grep -o '"harmless":[0-9]*' | head -1 | cut -d':' -f2)
MALICIOUS=$(echo "$STATUS_RESULT" | grep -o '"malicious":[0-9]*' | head -1 | cut -d':' -f2)
SUSPICIOUS=$(echo "$STATUS_RESULT" | grep -o '"suspicious":[0-9]*' | head -1 | cut -d':' -f2)
UNDETECTED=$(echo "$STATUS_RESULT" | grep -o '"undetected":[0-9]*' | head -1 | cut -d':' -f2)

[ -z "$HARMLESS" ] && HARMLESS=0
[ -z "$MALICIOUS" ] && MALICIOUS=0
[ -z "$SUSPICIOUS" ] && SUSPICIOUS=0
[ -z "$UNDETECTED" ] && UNDETECTED=0

FILE_ESC=$(json_escape "$FILE")
FULL_PATH_ESC=$(json_escape "$FULL_PATH")
SCAN_TEXT_ESC=$(json_escape "$SCAN_TEXT")

curl -s --max-time 15 -X POST "https://shuffler.io/api/v1/hooks/webhook_fab2c4de-00ad-448d-b1bd-41d514b47eaf" \
     -H "Content-Type: application/json" \
     -d "{\"file\":\"$FILE_ESC\",\"full_path\":\"$FULL_PATH_ESC\",\"analysis_id\":\"$ANALYSIS_ID\",\"link\":\"https://www.virustotal.com/gui/file/$ANALYSIS_ID\",\"text\":\"$SCAN_TEXT_ESC\",\"harmless\":$HARMLESS,\"malicious\":$MALICIOUS,\"suspicious\":$SUSPICIOUS,\>

echo "[$(date)] Sent completed result to Bale & Shuffle webhook - $FILE | ID: $ANALYSIS_ID | Malicious: $MALICIOUS | Undetected: $UNDETECTED" >> /var/ossec/logs/active-responses.log
