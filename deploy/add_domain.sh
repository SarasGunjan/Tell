#!/usr/bin/env bash
# Serve Tell on your own domain with HTTPS, keeping the existing sslip.io address.
# First, at your registrar, add DNS "A" records pointing to the server IP:  @ -> IP  and  www -> IP
# Then: bash deploy/add_domain.sh yourname.tech
set -euo pipefail

DOMAIN="${1:?usage: bash deploy/add_domain.sh yourdomain.tld}"
HOST="${TELL_HOST:-root@149.28.52.109}"
SSH_KEY="${TELL_SSH_KEY:-$HOME/.ssh/tell_vultr_ed25519}"
IP="${HOST#*@}"
OLD="${IP//./-}.sslip.io"

# Only include www if it already points at the server
NAMES=("$DOMAIN")
for n in "$DOMAIN" "www.$DOMAIN"; do
  got="$(dig +short A "$n" @1.1.1.1 | tail -1)"
  if [ "$got" = "$IP" ]; then echo "DNS ok: $n -> $IP"
  elif [ "$n" = "$DOMAIN" ]; then echo "DNS for $n is '${got:-none}', not $IP. Fix the A record and wait a few minutes." >&2; exit 1
  else echo "Skipping www.$DOMAIN (DNS is '${got:-none}')"; continue; fi
  [ "$n" = "$DOMAIN" ] || NAMES+=("$n")
done

ssh -i "$SSH_KEY" -o BatchMode=yes "$HOST" bash -s -- "$OLD" "${NAMES[@]}" <<'REMOTE'
set -euo pipefail
OLD="$1"; shift
# Add the new names next to the existing one (idempotent), then extend the certificate
for n in "$@"; do grep -qw "$n" /etc/nginx/sites-available/tell || sed -i "/server_name/ s/$OLD/$OLD $n/" /etc/nginx/sites-available/tell; done
nginx -t && systemctl reload nginx
args=(-d "$OLD"); for n in "$@"; do args+=(-d "$n"); done
certbot --nginx --expand --non-interactive --agree-tos --redirect --register-unsafely-without-email --cert-name "$OLD" "${args[@]}"
REMOTE

curl -sS -o /dev/null -w "https://$DOMAIN -> %{http_code}\n" "https://$DOMAIN/api/status"
