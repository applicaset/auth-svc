package authsvc

import (
	"context"
	"time"
)

type Service interface {
	GenerateToken(ctx context.Context, userUUID string) (res *AccessTokenResponse, err error)
	RefreshToken(ctx context.Context, refreshToken string) (res *AccessTokenResponse, err error)
	ValidateToken(ctx context.Context, accessToken string) (res *ValidateTokenResponse, err error)
}

type ValidateTokenResponse struct {
	UserUUID  string
	ExpiresAt *time.Time
}

type AccessTokenResponse struct {
	AccessToken  string
	ExpiresAt    *time.Time
	RefreshToken *string
}
