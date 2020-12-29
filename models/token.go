package models

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const tokenSecret = "S321asas41SDFcxvASa324assadfCRET"

type Token struct {
	Token  string    `json:"refreshToken"`
	Expiry time.Time `json:"expiry"`
	User   User
	Claims TokenClaims
}

type TokenClaims struct {
	UserID    uint   `json:"user"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Role      string `json:"role"`
	jwt.StandardClaims
}

func (t *Token) GenerateJWT(u User, expiry time.Time) error {
	t.Expiry = expiry
	t.User = u
	t.Claims = TokenClaims{
		u.ID,
		u.Email,
		u.FirstName,
		u.LastName,
		u.Role,
		jwt.StandardClaims{
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: t.Expiry.Unix(),
			Issuer:    "",
		},
	}
	var err error
	newWith := jwt.NewWithClaims(jwt.SigningMethodHS256, t.Claims)
	t.Token, err = newWith.SignedString([]byte(tokenSecret))
	if err != nil {
		return err
	}
	return nil
}

func (t *Token) GenerateCookie(path string) *http.Cookie {
	c := http.Cookie{
		Name:     "refresh",
		Value:    t.Token,
		Expires:  t.Expiry,
		Path:     path,
		HttpOnly: true,
	}
	return &c
}

func ValidateToken(token string) (*TokenClaims, error) {
	parsed, err := jwt.ParseWithClaims(token, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Error decoding token.")
		}
		return []byte(tokenSecret), nil
	})
	if err != nil {
		return nil, err
	}
	claims := parsed.Claims.(*TokenClaims)
	if parsed.Valid == false {
		return nil, fmt.Errorf("Invalid token")
	}
	return claims, nil
}
