package authsvc

import (
	"context"
	"github.com/nasermirzaei89/jwt"
	"github.com/pkg/errors"
	"time"
)

type service struct {
	expiresInSec int64
	alg          jwt.Algorithm
	privateKey   []byte
	publicKey    []byte
}

func (svc *service) GenerateToken(_ context.Context, userUUID string) (*AccessTokenResponse, error) {
	at := jwt.New(svc.alg)

	now := time.Now()

	expiresAt := now.Add(time.Second * time.Duration(svc.expiresInSec))

	at.SetSubject(userUUID)
	at.SetExpirationTime(expiresAt)

	accessToken, err := jwt.Sign(at, svc.privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "error on sign access token")
	}

	rt := jwt.New(svc.alg)

	rt.SetSubject(userUUID)

	refreshToken, err := jwt.Sign(rt, svc.privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "error on sign refresh token")
	}

	rsp := AccessTokenResponse{
		AccessToken:  accessToken,
		ExpiresAt:    &expiresAt,
		RefreshToken: &refreshToken,
	}

	return &rsp, nil
}

func (svc *service) RefreshToken(_ context.Context, refreshToken string) (*AccessTokenResponse, error) {
	err := jwt.Verify(refreshToken, svc.publicKey)
	if err != nil {
		// TODO: handle error
		return nil, errors.Wrap(err, "error on verify refresh token")
	}

	rt, err := jwt.Parse(refreshToken)
	if err != nil {
		return nil, errors.Wrap(err, "error on parse refresh token")
	}

	userUUID, err := rt.GetSubject()
	if err != nil {
		return nil, errors.Wrap(err, "error on get refresh token subject")
	}

	// TODO: check refresh token algorithm

	at := jwt.New(svc.alg)

	now := time.Now()

	expiresAt := now.Add(time.Second * time.Duration(svc.expiresInSec))

	at.SetSubject(userUUID)
	at.SetExpirationTime(expiresAt)

	accessToken, err := jwt.Sign(at, svc.privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "error on sign access token")
	}

	rsp := AccessTokenResponse{
		AccessToken:  accessToken,
		ExpiresAt:    &expiresAt,
		RefreshToken: &refreshToken,
	}

	return &rsp, nil
}

func (svc *service) ValidateToken(_ context.Context, accessToken string) (*ValidateTokenResponse, error) {
	err := jwt.Verify(accessToken, svc.publicKey)
	if err != nil {
		// TODO: handle error
		return nil, errors.Wrap(err, "error on verify access token")
	}

	at, err := jwt.Parse(accessToken)
	if err != nil {
		return nil, errors.Wrap(err, "error on parse access token")
	}

	userUUID, err := at.GetSubject()
	if err != nil {
		return nil, errors.Wrap(err, "error on get refresh token subject")
	}

	expiresAt := new(time.Time)

	*expiresAt, err = at.GetExpirationTime()
	if err != nil {
		if errors.Is(err, jwt.ErrClaimNotFound) {
			expiresAt = nil
		} else {
			return nil, errors.Wrap(err, "error on get expiration time")
		}
	}

	rsp := ValidateTokenResponse{
		UserUUID:  userUUID,
		ExpiresAt: expiresAt,
	}

	return &rsp, nil
}

func New(options ...Option) Service {
	svc := service{}

	for i := range options {
		options[i](&svc)
	}

	return &svc
}
