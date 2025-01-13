package jwt

import (
	"context"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/rs/zerolog/log"
)

type Validator interface {
	Validate(jwtString string) (string, bool)
}

func NewValidator(jwkUrl string, certKeyId string, usernameField string) Validator {
	return &validator{
		jwkUrl:        jwkUrl,
		certKeyId:     certKeyId,
		UsernameField: usernameField,
	}
}

type validator struct {
	jwkUrl        string
	certKeyId     string
	UsernameField string
}

func (j *validator) Validate(jwtString string) (string, bool) {
	set, err := jwk.Fetch(context.Background(), j.jwkUrl)
	if err != nil {
		log.Error().Err(err).Send()
		return "failed to fetch jwk", false
	}

	key, found := set.LookupKeyID(j.certKeyId)
	if !found {
		log.Error().Err(err).Send()
		return "keycloak cert id not found", false
	}

	if token, err := jwt.ParseString(jwtString, jwt.WithKey(key.Algorithm(), key)); err == nil {
		if userId, ok := token.Get(j.UsernameField); ok {
			return userId.(string), userId.(string) != ""
		} else {
			return "", false
		}
	} else {
		log.Error().Err(err).Send()
		return "", false
	}
}
