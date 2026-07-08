#!/bin/sh
read -r input

echo "[$(date)] DEBUG - Raw Input: $input" >> /var/ossec/logs/active-responses.log

# تابع escape کردن مقادیر برای JSON امن
json_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g'
}

# --- استخراج IP ---
# اول دنبال فیلدهای رایج srcip / src_ip می‌گردیم (این‌ها معمولا توسط Wazuh پر می‌شن)
SRC_IP=$(echo "$input" | grep -oE '"srcip"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n1 | cut -d'"' -f4)

if [ -z "$SRC_IP" ]; then
    SRC_IP=$(echo "$input" | grep -oE '"src_ip"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n1 | cut -d'"' -f4)
fi

# اگه هیچ‌کدوم پیدا نشد، fallback: اولین چیزی که شکل یک IPv4 معتبر داره رو از کل ورودی می‌گیریم
if [ -z "$SRC_IP" ]; then
    SRC_IP=$(echo "$input" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)
fi

# استخراج اطلاعات کمکی (اختیاری، برای context بهتر توی Shuffle)
RULE_ID=$(echo "$input" | grep -oE '"rule"[[:space:]]*:[[:space:]]*\{[^}]*"id"[[:space:]]*:[[:space:]]*"?[0-9]+"?' | grep -oE '[0-9]+' | tail -n1)
RULE_DESC=$(echo "$input" | grep -oE '"description"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n1 | cut -d'"' -f4)

echo "[$(date)] DEBUG - Extracted IP: $SRC_IP | Rule: $RULE_ID | Desc: $RULE_DESC" >> /var/ossec/logs/active-responses.log

if [ -z "$SRC_IP" ]; then
    echo "[$(date)] ERROR - No IP found in alert input" >> /var/ossec/logs/active-responses.log
    exit 1
fi

# --- ارسال IP به وبهوک Shuffle ---
IP_ESC=$(json_escape "$SRC_IP")
DESC_ESC=$(json_escape "$RULE_DESC")

# !! جای این آدرس رو با آدرس وبهوک واقعی Shuffle خودت (مخصوص ورک‌فلوی اسکن IP) عوض کن !!
SHUFFLE_WEBHOOK_URL="https://shuffler.io/api/v1/hooks/webhook_REPLACE_ME"

curl -s --max-time 15 -X POST "https://shuffler.io/api/v1/hooks/webhook_93822b27-2cd3-403a-aef9-d2c272dfe2f7" \
     -H "Content-Type: application/json" \
     -d "{\"ip\":\"$IP_ESC\",\"rule_id\":\"$RULE_ID\",\"description\":\"$DESC_ESC\",\"time\":\"$(date '+%Y-%m-%d %H:%M:%S')\"}" > /dev/null

echo "[$(date)] Sent IP to Shuffle webhook - IP: $SRC_IP | Rule: $RULE_ID" >> /var/ossec/logs/active-responses.log
