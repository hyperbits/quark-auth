package controllers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"quark-auth/models"
	"strconv"

	"github.com/hyperbits/quark/crypto"
	"github.com/hyperbits/quark/response"

	"github.com/gorilla/mux"
)

type UpdateUserRequest struct {
	ID               int            `json:"id"`
	Email            string         `json:"email"`
	FirstName        string         `json:"firstName"`
	LastName         string         `json:"lastName"`
	Password         string         `json:"password"`
	Role             string         `json:"role"`
	VerificationCode sql.NullString `json:"-"`
	Verified         int            `json:"verified"`
	Active           int            `json:"active"`
}

func (c *AuthController) GetUser() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		vars := mux.Vars(req)
		id, _ := strconv.Atoi(vars["id"])

		var user models.User
		if result := c.App.DB.First(&user, id); result.Error != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not get user", result.Error.Error())
			return
		}
		var userMap, err = user.UserWithDetail(c.App)
		if err != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not get user details", err.Error())
			return
		}
		response.RespondWithJSON(w, http.StatusOK, userMap)
	})
}

func (c *AuthController) GetUsers() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// search := req.FormValue("search")
		sort := req.FormValue("$sort")
		take, _ := strconv.Atoi(req.FormValue("$take"))
		skip, _ := strconv.Atoi(req.FormValue("$skip"))
		if take > 1000 || take < 1 {
			take = 1000
		}
		if skip < 0 {
			skip = 0
		}
		// TODO: filtering and sort
		var sortAsc = true
		if sort == "" {
			sort = "id"
		}
		var query = c.App.DB

		req.ParseForm()
		for key, values := range req.Form {
			if string(key[0]) != "$" {
				for _, value := range values {
					if string(value[0]) == "!" {
						query = query.Where(fmt.Sprintf("%s <> ?", key), value[1:])
					} else {
						query = query.Where(fmt.Sprintf("%s = ?", key), value)
					}
				}
			}
		}
		var users []models.User
		if result := query.Limit(take).Offset(skip).Order(sort, sortAsc).Find(&users); result.Error != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not get users", result.Error.Error())
			return
		}
		response.RespondWithJSON(w, http.StatusOK, users)
	})
}

func (c *AuthController) UpdateUser() http.Handler {
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
		user.Active = int(ur["active"].(float64))
		user.Verified = int(ur["verified"].(float64))
		user.Role = ur["role"].(string)

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

func (c *AuthController) CreateUser() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ur UpdateUserRequest
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&ur); err != nil {
			response.RespondWithError(w, http.StatusBadRequest, "Invalid request")
			return
		}
		defer r.Body.Close()

		var count = 0
		var u models.User
		if result := c.App.DB.Table("users").Where(&models.User{Email: ur.Email}).Count(&count); result.Error != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not check if user exists", result.Error.Error())
			return
		}
		if count > 0 {
			response.RespondWithError(w, http.StatusConflict, "User already exists with that email")
			return
		}

		hashed, saltErr := crypto.HashAndSalt([]byte(u.Password))
		if saltErr != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not generate password", saltErr.Error())
			return
		}
		u.Email = ur.Email
		u.FirstName = ur.FirstName
		u.LastName = ur.LastName
		u.Active = ur.Active
		u.Verified = ur.Verified
		u.Role = ur.Role
		u.Password = string(hashed)

		if err := c.App.DB.Create(&u).Error; err != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not create user", err.Error())
			return
		}
		response.RespondWithJSON(w, http.StatusOK, u)
	})
}

func (c *AuthController) DeleteUser() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		vars := mux.Vars(req)
		id, _ := strconv.Atoi(vars["id"])

		you, _ := strconv.Atoi(req.Header.Get("uid"))

		if you == id {
			response.RespondWithError(w, http.StatusBadRequest, "Cannot delete yourself")
			return
		}

		var user models.User
		if result := c.App.DB.First(&user, id); result.Error != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not get user", result.Error.Error())
			return
		}

		if result := c.App.DB.Delete(&user); result.Error != nil {
			response.RespondAndLogError(w, http.StatusInternalServerError, "Could not delete user", result.Error.Error())
			return
		}
		response.RespondWithJSON(w, http.StatusOK, id)
	})
}
