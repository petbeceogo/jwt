package pagetoken

import (
	"errors"

	"github.com/petbeceogo/dyna"
	"github.com/petbeceogo/jwt"
)

var (
	_Empty          = Payload{}
	ErrInvalidToken = errors.New("invalid page token")
)

type (
	Tokenizer struct {
		Secret                []byte
		PageSize              int
		EmptyTokenIsFirstMode bool
	}
)

func (t *Tokenizer) Generate(payload Payload) (Token, error) {
	if payload.PageSize == 0 {
		payload.PageSize = t.PageSize
	}

	token, err := jwt.SignWithHS256(payload.ToMap(), t.Secret)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (t *Tokenizer) Parse(token Token) (Payload, error) {
	if len(token) == 0 {
		if t.EmptyTokenIsFirstMode {
			return Payload{
				LastID:   "",
				PageSize: t.PageSize,
			}, nil
		} else {
			return _Empty, ErrInvalidToken
		}
	}

	json, err := jwt.ParseWithHMAC(token, t.Secret)
	if err != nil {
		return _Empty, ErrInvalidToken
	}
	lastID, err := dyna.StringMapValue(json, "lastID")
	if err != nil {
		return _Empty, ErrInvalidToken
	}
	pageSize, err := dyna.IntMapValue(json, "pageSize")
	if err != nil {
		return _Empty, ErrInvalidToken
	}

	return Payload{
		LastID:   lastID,
		PageSize: pageSize,
	}, nil
}

func NewTokenizer(
	secret []byte,
	pageSize int,
	emptyTokenIsFirstMode bool,
) *Tokenizer {
	return &Tokenizer{
		Secret:                secret,
		PageSize:              pageSize,
		EmptyTokenIsFirstMode: emptyTokenIsFirstMode,
	}
}
