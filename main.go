package main

import (
	"attendance-taking/attendance"
	"net/http"
)

func main() {
	http.HandleFunc("/", attendance.Index)
	http.HandleFunc("/admin", attendance.Admin)
	http.HandleFunc("/attendance", attendance.Attendance)
	http.HandleFunc("/login", attendance.Login)
	http.HandleFunc("/logout", attendance.Logout)
	http.HandleFunc("/upload", attendance.Upload)
	http.HandleFunc("/submit", attendance.Submit)
	http.HandleFunc("/export", attendance.Export)
	http.Handle("/favicon.ico", http.NotFoundHandler())
	http.ListenAndServe(":5332", nil)
}
