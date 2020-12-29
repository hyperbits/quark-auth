package models

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"github.com/hyperbits/quark"
	"sherkston-trailer-rentals/util"
	"strings"

	"github.com/jinzhu/gorm"
)

type User struct {
	gorm.Model
	Email            string `json:"email"`
	FirstName        string `json:"firstName"`
	LastName         string `json:"lastName"`
	Password         string `json:"-"`
	Role             string `json:"role"`
	VerificationCode string `json:"verificationCode"`
	Verified         int    `json:"verified"`
	Active           int    `json:"active"`

	RefreshTokens  []RefreshToken
	PasswordResets []PasswordReset
}

func (user *User) BeforeCreate(scope *gorm.Scope) error {
	scope.SetColumn("VerificationCode", user.GenerateVerificationCode())
	scope.SetColumn("Role", "user")
	return nil
}

func (u *User) GenerateVerificationCode() string {
	code := util.RandStringBytesMaskImprSrc(6)
	code = strings.ToUpper(code)
	code = code[:3] + "-" + code[3:]
	return code
}

func (user *User) SendEmail(email, subject string, data map[string]interface{}) error {

	plain, html, err := util.GetRequestEmailContent("message", data)
	if err != nil {
		return err
	}

	return quark.SendEmail("", email, subject, plain, html)
}

func (user *User) EmailWelcome(app *quark.App) error {

	var data = make(map[string]interface{})
	data["firstName"] = user.FirstName
	data["lastName"] = user.LastName
	data["email"] = user.Email
	data["role"] = user.Role
	data["appName"] = util.GetAppName()

	plain, err := app.Template("welcome", "txt", data)
	if err != nil {
		return err
	}
	html, err := app.Template("welcome", "html", data)
	if err != nil {
		return err
	}
	return quark.SendEmail("You", user.Email, os.Getenv("EMAIL_SUBJECT_WELCOME"), plain, html)
}

func (user *User) EmailVerificationCode(app *quark.App) error {
	// generate base 64 url
	urlCode := base64.StdEncoding.EncodeToString([]byte(user.Email)) + "." + base64.StdEncoding.EncodeToString([]byte(user.VerificationCode))
	url := util.GetAppHostname() + "verify/" + urlCode

	var data = make(map[string]interface{})
	data["firstName"] = user.FirstName
	data["lastName"] = user.LastName
	data["email"] = user.Email
	data["role"] = user.Role
	data["url"] = url
	data["code"] = user.VerificationCode
	data["appName"] = util.GetAppName()

	plain, err := app.Template("email-verification", "txt", data)
	if err != nil {
		return err
	}
	html, err := app.Template("email-verification", "html", data)
	if err != nil {
		return err
	}
	return quark.SendEmail("You", user.Email, os.Getenv("EMAIL_SUBJECT_VERIFY"), plain, html)
}

func (user *User) UpdateDetails(details map[string]interface{}, app *quark.App) error {

	userJSON, err := json.Marshal(user)
	if err != nil {
		return err
	}
	var userMap map[string]interface{}
	json.Unmarshal(userJSON, &userMap)
	for k, v := range details {
		skip := false
		for kk := range userMap {
			if kk == k {
				skip = true
			}
			if k == "password" || k == "confirmPassword" {
				skip = true
			}
		}
		if skip == false {
			stringValue := fmt.Sprintf("%v", v)
			var detail UserDetail
			if result := app.DB.Where(UserDetail{Name: k, UserID: user.ID}).Assign(UserDetail{Value: stringValue}).FirstOrCreate(&detail); result.Error != nil {
				return err
			}
		}
	}
	return nil
}

func (user *User) UserWithDetail(app *quark.App) (detailMap map[string]interface{}, err error) {

	userJSON, err := json.Marshal(user)
	if err != nil {
		return nil, err
	}
	var userMap map[string]interface{}
	json.Unmarshal(userJSON, &userMap)

	var details []UserDetail
	if result := app.DB.Where("user_id = ?", user.ID).Find(&details); result.Error != nil {
		return nil, err
	}

	for _, detail := range details {
		userMap[detail.Name] = detail.Value
	}

	return userMap, nil
}
