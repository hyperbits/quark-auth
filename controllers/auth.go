package controllers

import (
	"encoding/json"
	"log"
	"net/http"
	"quark-auth/models"
	"time"

	"github.com/hyperbits/quark/crypto"
	"github.com/hyperbits/quark/response"
)

type AuthRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (c *AuthController) Authenticate() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		var a AuthRequest
		if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
			response.RespondWithError(w, http.StatusBadRequest, "Invalid request")
			return
		}
		defer r.Body.Close()

		var user models.User
		if result := c.App.DB.Where(&models.User{Email: a.Email}).First(&user); result.Error != nil {
			response.RespondWithError(w, http.StatusUnauthorized, "Invalid credential")
			return
		}
		valid, err := crypto.CompareHashed(user.Password, []byte(a.Password))
		if valid == false || err != nil {
			response.RespondWithError(w, http.StatusUnauthorized, "Invalid credentials")
			return
		}
		if user.Verified == 0 {
			response.RespondWithError(w, http.StatusForbidden, "Email verification required")
			return
		}
		if user.Active == 0 {
			response.RespondWithError(w, http.StatusForbidden, "Account disabled")
			return
		}

		var rt = &models.RefreshToken{}
		refresh, access, err := rt.GenerateTokens(user)
		if err != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not generate tokens", err.Error())
			return
		}

		rt.Token = refresh.Token
		rt.Expiry = refresh.Expiry
		rt.UserID = user.ID

		if err := c.App.DB.Create(&rt).Error; err != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not create refresh token", err.Error())
			return
		}

		var activity = &models.UserActivity{}
		activity.Track(user.ID, "login", r)
		if err := c.App.DB.Create(&activity).Error; err != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not save activity", err.Error())
			return
		}

		// Set refresh token, http only
		http.SetCookie(w, refresh.GenerateCookie("/"))

		response.RespondWithJSON(w, http.StatusOK, map[string]string{"token": access.Token, "expires": access.Expiry.Format("2006-01-02 15:04:05")})
	})
}

func (c *AuthController) AuthRefresh() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		var refresh string
		for _, cookie := range r.Cookies() {
			if cookie.Name == "refresh" {
				refresh = cookie.Value
			}
		}
		if refresh == "" {
			response.RespondWithError(w, http.StatusBadRequest, "Token not provided")
			return
		}
		var rt = &models.RefreshToken{}
		valid, err := rt.ValidateRefreshToken(refresh)
		if err != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not check validity", err.Error())
			return
		}
		if valid == false {
			response.RespondWithError(w, http.StatusForbidden, "Invalid token")
			return
		}

		result := c.App.DB.Where(&models.RefreshToken{Token: refresh}).First(&rt)
		if result.Error != nil {
			if result.RecordNotFound() {
				response.RespondWithError(w, http.StatusBadRequest, "Token not found")
				return
			} else {
				response.RespondAndLogError(w, http.StatusInternalServerError, "Could not get token", result.Error.Error())
				return
			}
		}
		// if refresh token has expired return 401
		// TODO: Delete token
		if time.Now().After(rt.Expiry) {
			if result := c.App.DB.Delete(&rt); result.Error != nil {
				response.RespondAndLogError(w, http.StatusInternalServerError, "Authentication failure", result.Error.Error())
				return
			}
			response.RespondWithError(w, http.StatusForbidden, "Token expired")
			return
		}

		var user models.User
		if result := c.App.DB.First(&user, rt.UserID); result.Error != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not get user", result.Error.Error())
			return
		}
		if result := c.App.DB.Delete(&rt); result.Error != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Authentication failure", result.Error.Error())
			return
		}

		var newRt = &models.RefreshToken{}
		newRefresh, access, err := newRt.GenerateTokens(user)
		if err != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not generate tokens", err.Error())
			return
		}

		newRt.Token = newRefresh.Token
		newRt.Expiry = newRefresh.Expiry
		newRt.UserID = user.ID

		if result := c.App.DB.Create(&newRt); result.Error != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not create refresh token", result.Error.Error())
			return
		}

		var activity = &models.UserActivity{}
		activity.Track(user.ID, "login", r)
		if err := c.App.DB.Create(&activity).Error; err != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not save activity", err.Error())
			return
		}

		// Set refresh token, http only
		http.SetCookie(w, newRefresh.GenerateCookie("/"))

		response.RespondWithJSON(w, http.StatusOK, map[string]string{"token": access.Token, "expires": access.Expiry.Format("2006-01-02 15:04:05")})

	})
}

func (c *AuthController) AuthLogout() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		var refresh string
		for _, cookie := range r.Cookies() {
			if cookie.Name == "refresh" {
				refresh = cookie.Value
			}
		}
		if refresh == "" {
			response.RespondWithError(w, http.StatusBadRequest, "Token not provided")
			return
		}
		var rt = &models.RefreshToken{}
		valid, err := rt.ValidateRefreshToken(refresh)
		if err != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not check validity", err.Error())
			return
		}
		if valid == false {
			response.RespondWithError(w, http.StatusForbidden, "Invalid token")
			return
		}

		result := c.App.DB.Where(&models.RefreshToken{Token: refresh}).First(&rt)
		if result.Error != nil {
			if result.RecordNotFound() {
				response.RespondWithError(w, http.StatusBadRequest, "Token not found")
				return
			} else {
				response.RespondAndLogError(w, http.StatusInternalServerError, "Could not get token", result.Error.Error())
				return
			}
		}

		if result := c.App.DB.Delete(&rt); result.Error != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Authentication failure", result.Error.Error())
			return
		}

		var activity = &models.UserActivity{}
		activity.Track(rt.UserID, "logout", r)
		if err := c.App.DB.Create(&activity).Error; err != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not save activity", err.Error())
			return
		}

		c, err := r.Cookie("refresh")
		if err != nil {
			log.Fatal(err.Error())
		}
		c.Name = "delete"
		c.Value = ""
		c.Expires = time.Unix(1414414788, 1414414788000)

		// Set refresh token, http only
		http.SetCookie(w, c)

		response.RespondWithJSON(w, http.StatusOK, map[string]string{"logged-out": "1"})

	})
}
