package models

import (
	"encoding/base64"
	"os"
	"quark"
	"sherkston-trailer-rentals/util"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
)

type PasswordReset struct {
	gorm.Model
	User   User
	UserID uint   `json:"user"`
	Code   string `json:"code"`
	// Created time.Time `json:"created"`
	Expiry time.Time `json:"expiry"`
	Used   int       `json:"used"`
}

func (r *PasswordReset) GenerateResetCode() string {
	code := util.RandStringBytesMaskImprSrc(6)
	code = strings.ToUpper(code)
	code = code[:3] + "-" + code[3:]
	return code
}

func (r *PasswordReset) EmailResetCode(user User, app *quark.App) error {

	// generate base 64 url
	urlCode := base64.StdEncoding.EncodeToString([]byte(user.Email)) + "." + base64.StdEncoding.EncodeToString([]byte(r.Code))
	url := util.GetAppHostname() + "password/forgot/" + urlCode

	var data = make(map[string]interface{})
	data["firstName"] = user.FirstName
	data["lastName"] = user.LastName
	data["email"] = user.Email
	data["role"] = user.Role
	data["url"] = url
	data["code"] = r.Code
	data["appName"] = util.GetAppName()

	plain, err := app.Template("reset-password", "txt", data)
	if err != nil {
		return err
	}
	html, err := app.Template("reset-password", "html", data)
	if err != nil {
		return err
	}
	return quark.SendEmail("You", user.Email, os.Getenv("EMAIL_SUBJECT_RESET_PASSWORD"), plain, html)
}

func EmailPasswordChanged(user User, app *quark.App) error {

	var data = make(map[string]interface{})
	data["firstName"] = user.FirstName
	data["lastName"] = user.LastName
	data["email"] = user.Email
	data["role"] = user.Role
	data["appName"] = util.GetAppName()

	plain, err := app.Template("password-has-reset", "txt", data)
	if err != nil {
		return err
	}
	html, err := app.Template("password-has-reset", "html", data)
	if err != nil {
		return err
	}
	return quark.SendEmail("You", user.Email, os.Getenv("EMAIL_SUBJECT_PASSWORD_HAS_RESET"), plain, html)
}
