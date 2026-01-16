package passport

import (
	"errors"
)

var (
	ErrInvalidToken   = errors.New("invalid token format")
	ErrExpiredToken   = errors.New("expired token")
	ErrEmptySecretKey = errors.New("secret key is empty")
	ErrInvalidInput   = errors.New("invalid input for token generation")
)
