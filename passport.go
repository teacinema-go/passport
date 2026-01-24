package passport

import (
	"strconv"
	"strings"
	"time"
)

const (
	hmacDomain  = "PassportTokenAuth/v1"
	internalSep = "|"
	externalSep = "."
)

type Token struct {
	UserID string
	Iat    int64
	Exp    int64
	Mac    string
	Val    string
}

func (t *Token) VerifyToken(secretKey string) bool {
	serialized := serialize(
		base64UrlEncode(t.UserID),
		base64UrlEncode(strconv.FormatInt(t.Iat, 10)),
		base64UrlEncode(strconv.FormatInt(t.Exp, 10)),
	)
	expectedMac := computeHmac(secretKey, serialized)
	return equal(expectedMac, t.Mac)
}

func GenerateToken(secretKey, userID string, ttl time.Duration) *Token {
	issuedAt := currentUnix()
	expiresAt := issuedAt + int64(ttl.Seconds())

	userPart := base64UrlEncode(userID)
	iatPart := base64UrlEncode(strconv.FormatInt(issuedAt, 10))
	expPart := base64UrlEncode(strconv.FormatInt(expiresAt, 10))

	serialized := serialize(userPart, iatPart, expPart)
	mac := computeHmac(secretKey, serialized)

	token := strings.Join([]string{userPart, iatPart, expPart, mac}, externalSep)

	return &Token{
		UserID: userID,
		Iat:    issuedAt,
		Exp:    expiresAt,
		Mac:    mac,
		Val:    token,
	}
}

func ParseToken(token string) (*Token, error) {
	parts := strings.Split(token, externalSep)
	if len(parts) != 4 {
		return nil, ErrInvalidToken
	}

	userID, err := base64UrlDecode(parts[0])
	if err != nil {
		return nil, err
	}
	iatStr, err := base64UrlDecode(parts[1])
	if err != nil {
		return nil, err
	}
	expStr, err := base64UrlDecode(parts[2])
	if err != nil {
		return nil, err
	}
	iat, err := strconv.ParseInt(iatStr, 10, 64)
	if err != nil {
		return nil, err
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return nil, err
	}

	now := currentUnix()
	if exp < now {
		return nil, ErrExpiredToken
	}

	return &Token{
		UserID: userID,
		Iat:    iat,
		Exp:    exp,
		Mac:    parts[3],
		Val:    token,
	}, nil
}
