package models

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
)

type RefreshToken struct {
	gorm.Model
	User   User      `json:"user"`
	UserID uint      `json:"user_id"`
	Token  string    `json:"refreshToken" sql:"type:varchar(500)"`
	Expiry time.Time `json:"expiry"`
}

func (t *RefreshToken) GenerateTokens(u User) (Token, Token, error) {
	var refresh Token
	var access Token

	err := refresh.GenerateJWT(u, time.Now().Add(365*24*time.Hour))
	if err != nil {
		return refresh, access, err
	}

	err = access.GenerateJWT(u, time.Now().Add(20*time.Minute))
	if err != nil {
		return refresh, access, err
	}

	return refresh, access, nil
}

func (t *RefreshToken) ValidateRefreshToken(refresh string) (bool, error) {
	token, err := jwt.ParseWithClaims(refresh, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Error decoding token.")
		}
		return []byte(tokenSecret), nil
	})
	if err != nil {
		return false, err
	}
	//claims := token.Claims.(*TokenClaims)
	if token.Valid == false {
		return false, nil
	}
	return true, nil
}
