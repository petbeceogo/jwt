package jwt

import (
	gojwt "github.com/golang-jwt/jwt/v4"
)

func SignWithHS256(data map[string]interface{}, secret []byte) (string, error) {
	jwtdata := gojwt.MapClaims{}
	for field, val := range data {
		jwtdata[field] = val
	}

	token := gojwt.NewWithClaims(gojwt.SigningMethodHS256, jwtdata)
	tokenString, err := token.SignedString(secret)

	return tokenString, err
}

func ParseWithHMAC(tokenString string, secret []byte) (map[string]interface{}, error) {
	token, err := gojwt.Parse(tokenString, func(token *gojwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*gojwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}

		return secret, nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(gojwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, ErrInvalidToken
}
