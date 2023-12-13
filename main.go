package main

import (
	"encoding/csv"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

type user struct {
	StudentID string
	Name      string
	Password  []byte
}

var tpl *template.Template
var mapUsers = map[string]user{}
var mapSessions = map[string]string{}

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
	mapUsers["admin"] = user{"admin", "admin", hashPassword("password")} // don't do this irl
	loadStudentsFromCSV("students.csv")
}

func main() {
	http.HandleFunc("/", index)
	http.HandleFunc("/restricted", restricted)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/submitattendance", submitattendance)
	http.Handle("/favicon.ico", http.NotFoundHandler())
	http.ListenAndServe(":5332", nil)
}

func index(res http.ResponseWriter, req *http.Request) {
	myUser := getUser(res, req)
	err := tpl.ExecuteTemplate(res, "index.gohtml", myUser)
	fmt.Println(err)
}

func restricted(res http.ResponseWriter, req *http.Request) {
	myUser := getUser(res, req)
	if !alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	tpl.ExecuteTemplate(res, "restricted.gohtml", myUser)
}

func login(res http.ResponseWriter, req *http.Request) {
	if alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	// process form submission
	if req.Method == http.MethodPost {
		username := req.FormValue("username")
		password := req.FormValue("password")
		// check if user exist with username
		myUser, ok := mapUsers[username]
		if !ok {
			http.Error(res, "Username and/or password do not match", http.StatusUnauthorized)
			return
		}
		// Matching of password entered
		err := bcrypt.CompareHashAndPassword(myUser.Password, []byte(password))
		if err != nil {
			http.Error(res, "Username and/or password do not match", http.StatusForbidden)
			return
		}
		// create session
		id := uuid.NewV4()
		myCookie := &http.Cookie{
			Name:  "myCookie",
			Value: id.String(),
		}
		http.SetCookie(res, myCookie)
		mapSessions[myCookie.Value] = username
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	tpl.ExecuteTemplate(res, "login.gohtml", nil)
}

func logout(res http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	myCookie, _ := req.Cookie("myCookie")
	// delete the session
	delete(mapSessions, myCookie.Value)
	// remove the cookie
	myCookie = &http.Cookie{
		Name:   "myCookie",
		Value:  "",
		MaxAge: -1,
	}
	http.SetCookie(res, myCookie)

	http.Redirect(res, req, "/", http.StatusSeeOther)
}

func getUser(res http.ResponseWriter, req *http.Request) user {
	// get current session cookie
	myCookie, err := req.Cookie("myCookie")
	if err != nil {
		id := uuid.NewV4()
		myCookie = &http.Cookie{
			Name:  "myCookie",
			Value: id.String(),
		}

	}
	http.SetCookie(res, myCookie)

	// if the user exists already, get user
	var myUser user
	if username, ok := mapSessions[myCookie.Value]; ok {
		myUser = mapUsers[username]
	}

	return myUser
}

func alreadyLoggedIn(req *http.Request) bool {
	myCookie, err := req.Cookie("myCookie")
	if err != nil {
		return false
	}
	username := mapSessions[myCookie.Value]
	_, ok := mapUsers[username]
	return ok
}

func loadStudentsFromCSV(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		log.Fatal(err)
	}
	for _, record := range records {
		mapUsers[record[0]] = user{record[0], record[1], hashPassword("changeYourPassword")}
	}
}

func hashPassword(password string) []byte {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}
	return hashedPassword
}

func submitattendance(res http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	myUser := getUser(res, req)
	if req.Method == http.MethodPost {
		if myUser.StudentID == "admin" {
			http.Error(res, "Admin cannot submit attendance", http.StatusForbidden)
			return
		}

		// Open csv for appending timestamp
		file, err := os.Open("students.csv")
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		reader := csv.NewReader(file)
		records, err := reader.ReadAll()
		if err != nil {
			log.Fatal(err)
		}

		// Find the index of the current student
		var attendanceIndex int
		for i, row := range records {
			if row[0] == myUser.StudentID {
				attendanceIndex = i
				break
			}
		}

		// Update the "Attendance" column with the current timestamp
		if records[attendanceIndex][2] != "-" {
			http.Error(res, "Attendance already submitted", http.StatusForbidden)
			return
		} else {
			records[attendanceIndex][2] = time.Now().Format("2006-01-02 15:04:05")
		}

		// Create a new file for writing
		newFile, err := os.Create("students_attendance.csv")
		if err != nil {
			log.Fatal(err)
		}
		defer newFile.Close()

		// Write the updated CSV to the new file
		writer := csv.NewWriter(newFile)
		defer writer.Flush()

		// Write headers
		headers := records[0]
		err = writer.Write(headers)
		if err != nil {
			log.Fatal(err)
		}

		// Write rows
		err = writer.WriteAll(records[1:])
		if err != nil {
			log.Fatal(err)
		}

		// Rename the new file to replace the original file
		err = os.Rename("students_attendance.csv", "students.csv")
		if err != nil {
			log.Fatal(err)
		}

		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
}
