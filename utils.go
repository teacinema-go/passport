package passport

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"time"
)

func base64UrlEncode(data string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(data))
}

func base64UrlDecode(data string) (string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(data)
	return string(decoded), err
}

func equal(mac1, mac2 string) bool {
	return hmac.Equal([]byte(mac1), []byte(mac2))
}

func currentUnix() int64 {
	return time.Now().Unix()
}

func serialize(user, iat, exp string) string {
	return strings.Join([]string{hmacDomain, user, iat, exp}, internalSep)
}

func computeHmac(key, data string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
