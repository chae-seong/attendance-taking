// Package attendance implements a simple web application for students to submit their attendance
package attendance

import (
	"encoding/csv"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/joho/godotenv"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

// User is a struct to store User information
type User struct {
	StudentID string
	Name      string
	Password  []byte
}

// Student is a struct to store student information
type Student struct {
	StudentID  string
	Name       string
	Attendance string
}

var tpl *template.Template
var MapUsers = map[string]User{}
var MapSessions = map[string]string{}
var mutex sync.Mutex

func init() {
	tpl = template.Must(template.ParseGlob("./attendance/templates/*gohtml"))

	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		fmt.Println("Error loading .env file")
		return
	}
	// Read environment variables
	adminUsername := os.Getenv("ADMIN_USERNAME")
	adminPassword := os.Getenv("ADMIN_PASSWORD")

	MapUsers["admin"] = User{adminUsername, "admin", HashPassword(adminPassword)}
}

func Index(res http.ResponseWriter, req *http.Request) {
	myUser := getUser(res, req)
	err := tpl.ExecuteTemplate(res, "index.gohtml", myUser)
	fmt.Println(err)
}

func Admin(res http.ResponseWriter, req *http.Request) {
	myUser := getUser(res, req)
	if myUser.StudentID != "admin" {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	err := tpl.ExecuteTemplate(res, "admin.gohtml", myUser)
	fmt.Println(err)
}

func Attendance(res http.ResponseWriter, req *http.Request) {
	myUser := getUser(res, req)
	if !AlreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	if myUser.StudentID != "admin" {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	// Check if "students.csv" exists
	_, err := os.Stat("students.csv")
	if os.IsNotExist(err) {
		// "students.csv" does not exist, prompt admin to upload the file
		http.Error(res, "Please upload the student list first", http.StatusInternalServerError)
		return
	} else if err != nil {
		// Handle other errors if necessary
		log.Fatal(err)
		http.Error(res, "An error occurred while checking for the student list", http.StatusInternalServerError)
		return
	}

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

	// Convert CSV data to a slice of Student structs
	var students []Student
	for _, row := range records[1:] {
		student := Student{
			StudentID:  row[0],
			Name:       row[1],
			Attendance: row[2],
		}
		students = append(students, student)
	}

	tpl.ExecuteTemplate(res, "attendance.gohtml", students)
}

func Login(res http.ResponseWriter, req *http.Request) {
	if AlreadyLoggedIn(req) {
		if getUser(res, req).StudentID == "admin" {
			http.Redirect(res, req, "/admin", http.StatusSeeOther)
		} else {
			http.Redirect(res, req, "/", http.StatusSeeOther)
		}
		return
	}

	// process form submission
	if req.Method == http.MethodPost {
		username := req.FormValue("username")
		password := req.FormValue("password")

		if username != "admin" {
			// Check if "students.csv" exists
			_, err := os.Stat("students.csv")
			if os.IsNotExist(err) {
				// "students.csv" does not exist, prompt admin to upload the file
				http.Error(res, "Please get admin to upload student list first", http.StatusInternalServerError)
				return
			} else if err != nil {
				// Handle other errors if necessary
				log.Fatal(err)
				http.Error(res, "An error occurred while checking for the student list", http.StatusInternalServerError)
				return
			}

			LoadStudentsFromCSV("students.csv")
		}
		// check if User exist with username
		myUser, ok := MapUsers[username]
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
		MapSessions[myCookie.Value] = username

		if myUser.StudentID == "admin" {
			http.Redirect(res, req, "/admin", http.StatusSeeOther)
		} else {
			http.Redirect(res, req, "/", http.StatusSeeOther)
		}

		return
	}

	tpl.ExecuteTemplate(res, "login.gohtml", nil)
}

func Logout(res http.ResponseWriter, req *http.Request) {
	if !AlreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	myCookie, _ := req.Cookie("myCookie")
	// delete the session
	delete(MapSessions, myCookie.Value)
	// remove the cookie
	myCookie = &http.Cookie{
		Name:   "myCookie",
		Value:  "",
		MaxAge: -1,
	}
	http.SetCookie(res, myCookie)

	http.Redirect(res, req, "/", http.StatusSeeOther)
}

func getUser(res http.ResponseWriter, req *http.Request) User {
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

	// if the User exists already, get User
	var myUser User
	if username, ok := MapSessions[myCookie.Value]; ok {
		myUser = MapUsers[username]
	}

	return myUser
}

// AlreadyLoggedIn checks if the User is already logged in
// It returns true if the User is already logged in, and false otherwise
func AlreadyLoggedIn(req *http.Request) bool {
	myCookie, err := req.Cookie("myCookie")
	if err != nil {
		return false
	}
	username := MapSessions[myCookie.Value]
	_, ok := MapUsers[username]
	return ok
}

func Upload(res http.ResponseWriter, req *http.Request) {
	if !AlreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	myUser := getUser(res, req)
	if myUser.StudentID != "admin" {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	if req.Method == http.MethodPost {
		// open uploaded file
		file, _, err := req.FormFile("csvFile")
		if err != nil {
			log.Println("Error uploading file:", err)
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		defer file.Close()

		// save the uploaded file as "students.csv"
		savePath := "./students.csv"
		newFile, err := os.Create(savePath)
		if err != nil {
			log.Println("Error creating file:", err)
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		defer newFile.Close()

		_, err = io.Copy(newFile, file)
		if err != nil {
			log.Println("Error copying file:", err)
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}

		LoadStudentsFromCSV("students.csv")

		http.Redirect(res, req, "/attendance", http.StatusSeeOther)
		return
	}
}

// LoadStudentsFromCSV loads the student list from the CSV file
// It also adds the "Attendance" column to the CSV file if it doesn't already exist
func LoadStudentsFromCSV(filename string) {
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
	if len(records[0]) < 3 {
		records[0] = append(records[0], "Attendance")
		for i := range records[1:] {
			records[i+1] = append(records[i+1], "-")
		}
	}
	defaultPassword := os.Getenv("DEFAULT_PASSWORD")

	for _, record := range records[1:] {
		MapUsers[record[0]] = User{record[0], record[1], HashPassword(defaultPassword)}
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
}

// HashPassword hashes the password using bcrypt
// It returns the hashed password as a byte slice
// It is used to hash the password before storing it in the MapUsers
func HashPassword(password string) []byte {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}
	return hashedPassword
}

// Submit is the handler for the Submit page
// It allows students to submit their attendance by adding timestamp the "Attendance" column in the CSV file
func Submit(res http.ResponseWriter, req *http.Request) {
	if !AlreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	myUser := getUser(res, req)

	mutex.Lock()
	defer mutex.Unlock()

	if req.Method == http.MethodPost {
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
		var studentIndex int
		for i, row := range records {
			if row[0] == myUser.StudentID {
				studentIndex = i
				break
			}
		}

		// Update the "Attendance" column with the current timestamp
		if records[studentIndex][2] != "-" {
			http.Error(res, "Attendance already submitted", http.StatusForbidden)
			return
		}
		records[studentIndex][2] = time.Now().Format("2006-01-02 15:04:05")

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

// Export is the handler for the Export page
// It allows the admin to download the attendance list
func Export(res http.ResponseWriter, req *http.Request) {
	// Open the existing students.csv file
	file, err := os.Open("./students.csv")
	if err != nil {
		log.Println("Error opening students.csv:", err)
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Set the Content-Disposition header to specify the filename
	res.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=students_%s.csv", time.Now().Format("2006-01-02")))

	// Serve the file for download
	http.ServeContent(res, req, "", time.Now(), file)
}
