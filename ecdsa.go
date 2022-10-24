package jwt

import (
	gojwt "github.com/golang-jwt/jwt/v4"
)

func SignWithECPrivatePEM(data map[string]interface{}, privPEM []byte) (string, error) {
	privKey, err := gojwt.ParseECPrivateKeyFromPEM(privPEM)
	if err != nil {
		return "", err
	}

	jwtdata := gojwt.MapClaims{}
	for field, val := range data {
		jwtdata[field] = val
	}
	token := gojwt.NewWithClaims(gojwt.SigningMethodES256, jwtdata)
	tokenString, err := token.SignedString(privKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func ParseWithECDSAPublicPEM(tokenString string, pubPEM []byte) (map[string]interface{}, error) {
	pubKey, err := gojwt.ParseECPublicKeyFromPEM(pubPEM)
	if err != nil {
		return nil, err
	}

	token, err := gojwt.Parse(tokenString, func(t *gojwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*gojwt.SigningMethodECDSA); !ok {
			return nil, ErrInvalidToken
		}

		return pubKey, nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(gojwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, ErrInvalidToken
}
