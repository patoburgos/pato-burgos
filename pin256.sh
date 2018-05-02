#!/usr/bin/env bash -e

HOST=${1:-cloudflare.com}
FILENAME=${2:-${HOST%%.*}}

# For file naming, see https://support.ssl.com/Knowledgebase/Article/View/19/0/der-vs-crt-vs-cer-vs-pem-certificates-and-how-to-convert-them
# For HTTP Public Key Pinning (HPKP), see https://developer.mozilla.org/en-US/docs/Web/HTTP/Public_Key_Pinning
CERTIFICATE_PEM="${FILENAME}_certificate.ascii.crt"
CERTIFICATE_DER="${FILENAME}_certificate.crt"
PUBKEY_PEM="${FILENAME}_pubkey.ascii.key"
PUBKEY_DER="${FILENAME}_pubkey.key"
PUBKEY_SHA256="${FILENAME}_pubkey.sha256"
PUBKEY_PIN256="${FILENAME}_pubkey.ascii.pin256"

echo "Q" | openssl s_client -connect "${HOST}":443 -servername "${HOST}" 2>/dev/null | openssl x509 -outform pem > "${CERTIFICATE_PEM}"
openssl x509 -outform der < "${CERTIFICATE_PEM}" > "${CERTIFICATE_DER}"
openssl x509 -pubkey -noout < "${CERTIFICATE_PEM}"  > "${PUBKEY_PEM}"
openssl pkey -pubin -outform der < "${PUBKEY_PEM}" > "${PUBKEY_DER}"
openssl dgst -sha256 -binary < "${PUBKEY_DER}" > "${PUBKEY_SHA256}"
openssl enc -base64 < "${PUBKEY_SHA256}" > "${PUBKEY_PIN256}"

cat "${PUBKEY_PIN256}"
dumpasn1 -a "${PUBKEY_DER}" 2> /dev/null || openssl pkey -pubin -text -noout < "${PUBKEY_PEM}"
