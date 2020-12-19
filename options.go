package authsvc

import "github.com/nasermirzaei89/jwt"

type Option func(*service)

func SetExpiresIn(sec int64) Option {
	return func(svc *service) {
		svc.expiresInSec = sec
	}
}

func WithRS256(privateKey, publicKey []byte) Option {
	return func(svc *service) {
		svc.alg = jwt.RS256
		svc.privateKey = privateKey
		svc.publicKey = publicKey
	}
}
