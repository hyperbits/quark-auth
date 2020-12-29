package models

import (
	"net/http"
	"time"

	"github.com/jinzhu/gorm"
)

type UserActivity struct {
	gorm.Model
	User      User      `json:"user"`
	UserID    uint      `json:"user_id"`
	Client    string    `json:"client"`
	IPAddress string    `json:"sherkston-trailer-rentals"`
	Action    string    `json:"action"`
	Date      time.Time `json:"date"`
}

func (a *UserActivity) Track(userID uint, action string, r *http.Request) {
	a.UserID = userID
	a.IPAddress = ReadUserIP(r)
	a.Client = ReadUserAgent(r)
	a.Action = action
	a.Date = time.Now()
}
func ReadUserIP(r *http.Request) string {
	IPAddress := r.Header.Get("X-Real-Ip")
	if IPAddress == "" {
		IPAddress = r.Header.Get("X-Forwarded-For")
	}
	if IPAddress == "" {
		IPAddress = r.RemoteAddr
	}
	return IPAddress
}
func ReadUserAgent(r *http.Request) string {
	return r.Header.Get("User-Agent")
}
