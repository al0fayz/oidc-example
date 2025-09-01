package utils

import "errors"

var (
	ErrNotFound         = errors.New("not found")
	ErrAlreadyExists    = errors.New("already exists")
	ErrInvalidToken     = errors.New("invalid token")
	ErrTokenExpired     = errors.New("token expired")
	ErrTokenRevoked     = errors.New("token revoked")
	ErrConcurrentUpdate = errors.New("concurrent update")
	ErrTransaction      = errors.New("transaction error")
)
