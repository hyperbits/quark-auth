// main.go
package middleware

import (
	"fmt"
	"net/http"
	"github.com/hyperbits/quark-auth/models"
	"strings"

	"github.com/hyperbits/quark/response"
)

type AuthenticationMiddleware struct {
}

func (amw *AuthenticationMiddleware) Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		tokenString := r.Header.Get("Authorization")
		if len(tokenString) > 0 {
			tokenString = strings.Replace(tokenString, "Bearer ", "", 1)
			claims, err := models.ValidateToken(tokenString)
			if err != nil {
				response.RespondWithError(w, http.StatusUnauthorized, "Authorization Required")
				return
			}

			r.Header.Set("uid", fmt.Sprintf("%d", claims.UserID))
			r.Header.Set("email", claims.Email)
			r.Header.Set("role", claims.Role)
		}

		next.ServeHTTP(w, r)
	})
}

func (amw *AuthenticationMiddleware) Role(role string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		tokenString := r.Header.Get("Authorization")
		if len(tokenString) == 0 {
			response.RespondWithError(w, http.StatusUnauthorized, "Authorization Required")
			return
		}
		tokenString = strings.Replace(tokenString, "Bearer ", "", 1)
		claims, err := models.ValidateToken(tokenString)
		if err != nil {
			response.RespondWithError(w, http.StatusUnauthorized, "Authorization Required")
			return
		}
		roles := strings.Split(role, ",")
		roleFound := false
		for _, v := range roles {
			if claims.Role == v {
				roleFound = true
			}
		}
		if roleFound == false {
			response.RespondWithError(w, http.StatusUnauthorized, "Insufficient Security")
			return
		}

		r.Header.Set("uid", fmt.Sprintf("%d", claims.UserID))
		r.Header.Set("email", claims.Email)
		r.Header.Set("role", claims.Role)

		next.ServeHTTP(w, r)
	})
}
