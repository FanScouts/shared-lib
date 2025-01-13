package jwt

import (
	"context"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type Validator interface {
	Validate(jwtString string) (string, bool)
}

func NewValidator(jwkUrl string, certKeyId string, usernameField string) (Validator, error) {
	jwks, err := jwk.Fetch(context.Background(), jwkUrl)
	if err != nil {
		return nil, fmt.Errorf("could not load jwks")
	}
	return &validator{
		jwkUrl:        jwkUrl,
		certKeyId:     certKeyId,
		UsernameField: usernameField,
		jwks:          jwks,
	}, nil
}

type validator struct {
	jwkUrl        string
	certKeyId     string
	UsernameField string
	jwks          jwk.Set
}

func (j *validator) Validate(jwtString string) (string, bool) {

	key, found := j.jwks.LookupKeyID(j.certKeyId)
	if !found {
		return "certKey id not found", false
	}

	if token, err := jwt.ParseString(jwtString, jwt.WithKey(key.Algorithm(), key)); err == nil {
		if userId, ok := token.Get(j.UsernameField); ok {
			return userId.(string), userId.(string) != ""
		} else {
			return "", false
		}
	} else {
		// TODO add logging hooks
		return "", false
	}
}
