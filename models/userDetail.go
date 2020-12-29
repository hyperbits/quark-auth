package models

import (
	"github.com/jinzhu/gorm"
)

type UserDetail struct {
	gorm.Model
	Name   string `json:"name"`
	Value  string `json:"value"`
	User   User   `json:"user"`
	UserID uint   `json:"user_id"`
}
