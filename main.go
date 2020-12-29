package controllers

import (
	"fmt"
	"io/ioutil"
	"log"
	"quark"
	"quark-auth/controllers"
	middleware "quark-auth/middleware"
	"quark-auth/models"
	quarkModels "quark/models"
)

type Auth struct {
	quark.Mod
}

func (a *Auth) Setup(app *quark.App) {

	log.Print("Setting up Quark Auth")
	// Models
	app.DB.AutoMigrate(&models.User{})
	app.DB.AutoMigrate(&models.UserDetail{})
	app.DB.AutoMigrate(&models.RefreshToken{})
	app.DB.AutoMigrate(&models.PasswordReset{})
	app.DB.AutoMigrate(&models.UserActivity{})

	if err := a.InstallTemplates(app); err != nil {
		log.Fatal("Error installing templates")
	}

	// Routes
	amw := middleware.AuthenticationMiddleware{}
	c := controllers.AuthController{App: app}

	app.Post("/auth/login", c.Authenticate())
	app.Post("/auth/refresh", c.AuthRefresh())
	app.Post("/auth/logout", c.AuthLogout())

	app.Post("/user/check-email", c.CheckEmail())
	app.Post("/user/register", c.UserRegister())
	app.Post("/user/verify", c.UserVerifyEmail())
	app.Post("/user/verify/resend", c.UserResendVerificationCode())
	app.Post("/user/password/send-reset", c.UserSendResetCode())
	app.Post("/user/password/verify-reset", c.UserVerifyResetCode())
	app.Post("/user/password/reset", c.UserResetPassword())
	app.Post("/user/password/change", amw.Auth(c.UserChangePassword()))
	app.Get("/user/profile", amw.Auth(c.UserGetProfile()))
	app.Post("/user/profile", amw.Auth(c.UserUpdateProfile()))

	app.Get("/users/", amw.Role("admin", c.GetUsers()))
	app.Get("/users/{id:[0-9]+}", amw.Role("admin", c.GetUser()))
	app.Post("/users/", amw.Role("admin", c.CreateUser()))
	app.Post("/users/{id:[0-9]+}", amw.Role("admin", c.UpdateUser()))
	app.Delete("/users/{id:[0-9]+}", amw.Role("admin", c.DeleteUser()))

}
func (a *Auth) InstallTemplates(app *quark.App) error {
	var templates []quarkModels.Template
	if result := app.DB.Find(&templates); result.Error != nil {
		return result.Error
	}

	var templateNames = []string{"welcome", "reset-password", "password-has-reset", "email-verification"}
	for _, name := range templateNames {
		var foundTXT = false
		var foundHTML = false
		for _, template := range templates {
			if template.Name == name && template.Type == "txt" {
				foundTXT = true
			}
			if template.Name == name && template.Type == "html" {
				foundHTML = true
			}
		}
		if foundTXT == false {
			if err := a.InstallTemplate(app, name, "txt"); err != nil {
				return err
			}
		}
		if foundHTML == false {
			if err := a.InstallTemplate(app, name, "html"); err != nil {
				return err
			}
		}
	}

	return nil
}
func (a *Auth) InstallTemplate(app *quark.App, name, ext string) error {
	template, err := ioutil.ReadFile(fmt.Sprintf("templates/email/%s.%s", name, ext))
	if err != nil {
		return err
	}
	var t quarkModels.Template
	t.Name = name
	t.Type = ext
	t.Content = string(template)
	if err := app.DB.Create(&t).Error; err != nil {
		return err
	}
	return nil
}
