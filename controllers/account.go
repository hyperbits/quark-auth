package controllers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/hyperbits/quark-auth/models"
	"github.com/jinzhu/gorm"

	"github.com/hyperbits/quark/crypto"
	"github.com/hyperbits/quark/response"
)

type UserRegisrationRequest struct {
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Password  string `json:"password"`
}

func (c *AuthController) UserRegister() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ur UserRegisrationRequest
		if err := json.NewDecoder(r.Body).Decode(&ur); err != nil {
			response.RespondWithError(w, http.StatusBadRequest, "Invalid request")
			return
		}
		defer r.Body.Close()

		var exists models.User
		if result := c.App.DB.Where(&models.User{Email: ur.Email}).First(&exists); result.Error != nil {
			if result.Error != gorm.ErrRecordNotFound {
				response.RespondAndLogError(w, http.StatusInternalServerError, "Could not check if user exists", result.Error.Error())
				return
			}
		}

		hashed, saltErr := crypto.HashAndSalt([]byte(ur.Password))
		if saltErr != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not generate password", saltErr.Error())
			return
		}

		var user models.User
		user.Email = ur.Email
		user.Password = hashed
		user.FirstName = ur.FirstName
		user.LastName = ur.LastName
		user.Role = "user"
		user.Active = 0
		user.Verified = 0

		if err := c.App.DB.Create(&user).Error; err != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not create user", err.Error())
			return
		}

		if err := user.EmailVerificationCode(c.App); err != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not send email verification code", err.Error())
			return
		}

		response.RespondWithJSON(w, http.StatusCreated, map[string]string{"verified": "0"})
	})
}

type CheckEmailRequest struct {
	Email string `json:"email"`
}

func (c *AuthController) CheckEmail() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ur CheckEmailRequest
		if err := json.NewDecoder(r.Body).Decode(&ur); err != nil {
			response.RespondWithError(w, http.StatusBadRequest, "Invalid request")
			return
		}
		defer r.Body.Close()

		if ur.Email == "" {
			response.RespondWithJSON(w, http.StatusOK, "Ok")
			return
		}

		var user models.User
		if result := c.App.DB.Where(&models.User{Email: ur.Email}).First(&user); result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				response.RespondWithJSON(w, http.StatusOK, "Ok")
				return
			}
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not check if user exists", result.Error.Error())
			return
		}
		response.RespondWithError(w, http.StatusConflict, "User already exists with that email")
		return
	})
}

type VerifyEmailRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

func (c *AuthController) UserVerifyEmail() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ve VerifyEmailRequest
		if err := json.NewDecoder(r.Body).Decode(&ve); err != nil {
			response.RespondWithError(w, http.StatusBadRequest, "Invalid request")
			return
		}
		defer r.Body.Close()

		var user models.User
		if result := c.App.DB.Where(&models.User{Email: ve.Email}).First(&user); result.Error != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not verify email", result.Error.Error())
			return
		}
		if user.Verified == 1 {
			response.RespondWithJSON(w, http.StatusOK, map[string]string{"alreadyVerified": "1"})
			return
		}
		if user.VerificationCode != ve.Code {
			response.RespondWithError(w, http.StatusBadRequest, "Invalid code")
			return
		}
		user.Verified = 1
		user.Active = 1
		if result := c.App.DB.Save(&user); result.Error != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not verify", result.Error.Error())
			return
		}

		if err := user.EmailWelcome(c.App); err != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not send welcome email", err.Error())
			return
		}

		response.RespondWithJSON(w, http.StatusOK, map[string]string{"verified": "1"})
	})
}

type SendResetRequest struct {
	Email string `json:"email"`
}

func (c *AuthController) UserResendVerificationCode() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rr SendResetRequest
		if err := json.NewDecoder(r.Body).Decode(&rr); err != nil {
			response.RespondWithError(w, http.StatusBadRequest, "Invalid request")
			return
		}
		defer r.Body.Close()

		var user models.User
		if result := c.App.DB.Where(&models.User{Email: rr.Email}).First(&user); result.Error != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not verify email", result.Error.Error())
			return
		}
		if user.Verified == 1 {
			response.RespondWithJSON(w, http.StatusOK, map[string]string{"alreadyVerified": "1"})
			return
		}

		user.VerificationCode = user.GenerateVerificationCode()
		if result := c.App.DB.Save(&user); result.Error != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not verify", result.Error.Error())
			return
		}

		if err := user.EmailVerificationCode(c.App); err != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not send email verification code", err.Error())
			return
		}

		response.RespondWithJSON(w, http.StatusOK, map[string]string{"sent": "1"})
	})
}

func (c *AuthController) UserSendResetCode() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rr SendResetRequest
		if err := json.NewDecoder(r.Body).Decode(&rr); err != nil {
			response.RespondWithError(w, http.StatusBadRequest, "Invalid request")
			return
		}
		defer r.Body.Close()

		var user models.User
		if result := c.App.DB.Where(&models.User{Email: rr.Email}).First(&user); result.Error != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not send password reset code", result.Error.Error())
			return
		}

		pr := models.PasswordReset{}
		pr.UserID = user.ID
		// pr.Created = time.Now()
		pr.Expiry = time.Now().Local().Add(time.Hour * time.Duration(8))
		pr.Code = pr.GenerateResetCode()

		if err := c.App.DB.Create(&pr).Error; err != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not create password reset code", err.Error())
			return
		}

		if err := pr.EmailResetCode(user, c.App); err != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not email password reset code", err.Error())
			return
		}

		response.RespondWithJSON(w, http.StatusOK, map[string]string{"sent": "1"})
	})
}

type VerifyResetRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

func (c *AuthController) UserVerifyResetCode() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ve VerifyResetRequest
		if err := json.NewDecoder(r.Body).Decode(&ve); err != nil {
			response.RespondWithError(w, http.StatusBadRequest, "Invalid request")
			return
		}
		defer r.Body.Close()

		var user models.User
		if result := c.App.DB.Where(&models.User{Email: ve.Email}).First(&user); result.Error != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Verify email failure", result.Error.Error())
			return
		}
		var count = 0
		if result := c.App.DB.Table("password_resets").Where("code = ? and used = 0 and expiry > NOW()", ve.Code).Count(&count); result.Error != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Verify code failure", result.Error.Error())
			return
		}
		if count == 0 {
			response.RespondWithError(w, http.StatusBadRequest, "Invalid request")
			return
		}
		response.RespondWithJSON(w, http.StatusOK, map[string]string{"valid": "1"})
	})
}

type ResetPasswordRequest struct {
	Email           string `json:"email"`
	Code            string `json:"code"`
	NewPassword     string `json:"newPassword"`
	ConfirmPassword string `json:"confirmPassword"`
}

// TODO: Send password has changed email
func (c *AuthController) UserResetPassword() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rp ResetPasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&rp); err != nil {
			response.RespondWithError(w, http.StatusBadRequest, "Invalid request")
			return
		}
		defer r.Body.Close()

		if rp.NewPassword == "" {
			response.RespondWithError(w, http.StatusBadRequest, "New password empty")
			return
		}
		if rp.ConfirmPassword == "" {
			response.RespondWithError(w, http.StatusBadRequest, "Confirm password empty")
			return
		}
		if rp.NewPassword != rp.ConfirmPassword {
			response.RespondWithError(w, http.StatusBadRequest, "Passwords do not match")
			return
		}
		var user models.User
		if result := c.App.DB.Where(&models.User{Email: rp.Email}).First(&user); result.Error != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not get user", result.Error.Error())
			return
		}
		var reset models.PasswordReset
		result := c.App.DB.Where(&models.PasswordReset{Code: rp.Code, UserID: user.ID}).First(&reset)
		if result.Error != nil {
			if result.RecordNotFound() {
				response.RespondWithError(w, http.StatusBadRequest, "Invalid reset code")
				return
			} else {
				response.RespondAndLogError(w, http.StatusInternalServerError, "Could not get reset code", result.Error.Error())
				return
			}
		}
		if time.Now().After(reset.Expiry) {
			response.RespondWithError(w, http.StatusBadRequest, "Password reset expired")
			return
		}

		hashed, err := crypto.HashAndSalt([]byte(rp.NewPassword))
		if err != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not generate password", err.Error())
			return
		}
		user.Password = string(hashed)
		if result := c.App.DB.Save(&user); result.Error != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not update password", result.Error.Error())
			return
		}

		reset.Used = 1
		if result := c.App.DB.Save(&reset); result.Error != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not mark reset as used", result.Error.Error())
			return
		}

		// Notify user
		if err := models.EmailPasswordChanged(user, c.App); err != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not send notification", err.Error())
			return
		}

		var activity = &models.UserActivity{}
		activity.Track(user.ID, "password-reset", r)
		if err := c.App.DB.Create(&activity).Error; err != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not save activity", err.Error())
			return
		}

		response.RespondWithJSON(w, http.StatusOK, map[string]string{"reset": "1"})
	})
}

func (c *AuthController) UserGetProfile() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.Atoi(r.Header.Get("uid"))
		if err != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not fetch user", err.Error())
		}
		var user models.User
		if result := c.App.DB.First(&user, id); result.Error != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not get user", result.Error.Error())
			return
		}
		userMap, err := user.UserWithDetail(c.App)
		if err != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not get user details", err.Error())
			return
		}
		response.RespondWithJSON(w, http.StatusOK, userMap)
	})
}

type ChangePasswordRequest struct {
	ExistingPassword string `json:"existingPassword"`
	NewPassword      string `json:"newPassword"`
	ConfirmPassword  string `json:"confirmPassword"`
}

func (c *AuthController) UserChangePassword() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rp ChangePasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&rp); err != nil {
			response.RespondWithError(w, http.StatusBadRequest, "Invalid request")
			return
		}
		defer r.Body.Close()

		if rp.ExistingPassword == "" {
			response.RespondWithError(w, http.StatusBadRequest, "Existing password empty")
			return
		}
		if rp.NewPassword == "" {
			response.RespondWithError(w, http.StatusBadRequest, "New password empty")
			return
		}
		if rp.ConfirmPassword == "" {
			response.RespondWithError(w, http.StatusBadRequest, "Confirm password empty")
			return
		}
		if rp.NewPassword != rp.ConfirmPassword {
			response.RespondWithError(w, http.StatusBadRequest, "Passwords do not match")
			return
		}

		id, err := strconv.Atoi(r.Header.Get("uid"))
		if err != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not fetch user", err.Error())
		}
		var user models.User
		if result := c.App.DB.First(&user, id); result.Error != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not get user", result.Error.Error())
			return
		}
		valid, err := crypto.CompareHashed(user.Password, []byte(rp.ExistingPassword))
		if valid == false || err != nil {
			response.RespondWithError(w, http.StatusUnauthorized, "Invalid credentials")
			return
		}

		hashed, err := crypto.HashAndSalt([]byte(rp.NewPassword))
		if err != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not generate password", err.Error())
			return
		}
		user.Password = string(hashed)
		if result := c.App.DB.Save(&user); result.Error != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not update password", result.Error.Error())
			return
		}

		if err := models.EmailPasswordChanged(user, c.App); err != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not send notification", err.Error())
			return
		}

		var activity = &models.UserActivity{}
		activity.Track(user.ID, "password-change", r)
		if err := c.App.DB.Create(&activity).Error; err != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not save activity", err.Error())
			return
		}

		response.RespondWithJSON(w, http.StatusOK, map[string]string{"changed": "1"})
	})
}

type UserUpdateProfileRequest struct {
	Email                string `json:"email"`
	FirstName            string `json:"firstName"`
	LastName             string `json:"lastName"`
	SquareSandbox        int    `json:"squareSandbox"`
	SquareAPIKey         string `json:"squareAPIKey"`
	SquareAPIAccessToken string `json:"squareAPIAccessToken"`
}

func (c *AuthController) UserUpdateProfile() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ur map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&ur); err != nil {
			response.RespondWithError(w, http.StatusBadRequest, "Invalid request")
			return
		}
		defer r.Body.Close()

		var user models.User
		if result := c.App.DB.Where("ID = ?", ur["ID"]).First(&user); result.Error != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not get user", result.Error.Error())
			return
		}
		if ur["email"] != user.Email {
			var count = 0
			if result := c.App.DB.Table("users").Where("Email = ? and ID <> ?", ur["email"], ur["ID"]).Count(&count); result.Error != nil {
				response.RespondAndLogError(w, http.StatusInternalServerError, "Could not check if user exists", result.Error.Error())
				return
			}
			if count > 0 {
				response.RespondWithError(w, http.StatusConflict, "User already exists with that email")
				return
			} else {
				user.Email = ur["email"].(string)
			}
		}
		user.FirstName = ur["firstName"].(string)
		user.LastName = ur["lastName"].(string)

		if password, ok := ur["password"]; ok {
			hashed, err := crypto.HashAndSalt([]byte(password.(string)))
			if err != nil {
				response.RespondAndLogError(w, http.StatusInternalServerError, "Could not generate password", err.Error())
				return
			}
			user.Password = string(hashed)
		}

		if result := c.App.DB.Save(&user); result.Error != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not mark reset as used", result.Error.Error())
			return
		}

		if detailErr := user.UpdateDetails(ur, c.App); detailErr != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could update detail", detailErr.Error())
			return
		}

		response.RespondWithJSON(w, http.StatusOK, user)
	})
}
