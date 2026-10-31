CERT_DIR="cert"

openssl genpkey -algorithm RSA -out "$CERT_DIR/private-key.pem"

openssl rsa -in "$CERT_DIR/private-key.pem" -pubout -out "$CERT_DIR/public-key.pub"

echo "Keys have been generated in the $CERT_DIR/ folder."