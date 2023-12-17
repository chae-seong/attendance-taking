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
	"strings"
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

// MapUsers is a map that stores User objects with their corresponding keys.
var MapUsers = map[string]User{}

// MapSessions is a map that stores session IDs with their corresponding usernames.
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

// Index is an HTTP handler that serves the index page.
//
// It retrieves the user information using the getUser function, executes the "index.gohtml" template, and writes the result to the http.ResponseWriter.
// Any errors that occur during template execution are printed to the standard output.
//
// Parameters:
//   - res: http.ResponseWriter - the response writer to write the
//     generated HTML content.
//   - req: *http.Request - the incoming HTTP request.
func Index(res http.ResponseWriter, req *http.Request) {
	myUser := getUser(res, req)
	err := tpl.ExecuteTemplate(res, "index.gohtml", myUser)
	fmt.Println(err)
}

// Admin is an HTTP handler that serves the admin page.
//
// It retrieves the user information using the getUser function.
// If the user is not an admin, it redirects them to the index page.
// Otherwise, it executes the "admin.gohtml" template and writes the result to the http.ResponseWriter.
// Any errors that occur during template execution are printed to the standard output.
//
// Parameters:
//   - res: http.ResponseWriter - the response writer to write the
//     generated HTML content.
//   - req: *http.Request - the incoming HTTP request.
func Admin(res http.ResponseWriter, req *http.Request) {
	myUser := getUser(res, req)
	if myUser.StudentID != "admin" {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	err := tpl.ExecuteTemplate(res, "admin.gohtml", myUser)
	fmt.Println(err)
}

// Attendance is an HTTP handler that serves the attendance page.
//
// It retrieves the user information using the getUser function.
// If the user is not logged in, it redirects them to the index page.
// If the user is not an admin, it redirects them to the index page.
// Checks if the "students.csv" file exists, and if not, prompts the admin to upload the student list.
// Reads the CSV file, converts the data to a slice of Student structs, and executes the "attendance.gohtml" template, writing the result to the http.ResponseWriter.
//
// Parameters:
//   - res: http.ResponseWriter - the response writer to write the
//     generated HTML content.
//   - req: *http.Request - the incoming HTTP request.
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

// Login is an HTTP handler that serves the login page and processes
// the login form submission.
//
// If the user is already logged in, it redirects them to the index or admin page based on their role.
// If the user is not logged in, it processes the form submission, checks the user credentials, creates a session, and redirects to the index or admin page based on the user's role.
// If the username is "admin", it checks for the existence of "students.csv" and loads it into the MapUsers variable using the LoadStudentsFromCSV function.
//
// Parameters:
//   - res: http.ResponseWriter - the response writer to write the
//     generated HTML content.
//   - req: *http.Request - the incoming HTTP request.
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

// Logout is an HTTP handler that logs out the currently logged-in user.
//
// If the user is not logged in, it redirects them to the index page.
// Deletes the session and removes the cookie associated with it.
// Redirects the user to the index page after successful logout.
//
// Parameters:
//   - res: http.ResponseWriter - the response writer to write the
//     generated HTML content.
//   - req: *http.Request - the incoming HTTP request.
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

// AlreadyLoggedIn checks if a user is already logged in by examining the
// presence of a session cookie.
//
// Parameters:
//   - req: *http.Request - the incoming HTTP request.
//
// Returns:
//   - bool - true if the user is already logged in, false otherwise.
func AlreadyLoggedIn(req *http.Request) bool {
	myCookie, err := req.Cookie("myCookie")
	if err != nil {
		return false
	}
	username := MapSessions[myCookie.Value]
	_, ok := MapUsers[username]
	return ok
}

// Upload is an HTTP handler that handles file uploads for updating
// the student list (CSV file).
//
// If the user is not logged in, it redirects them to the index page.
// If the user is not an admin, it redirects them to the index page.
// Processes the uploaded CSV file, saves it as "students.csv", and loads the updated student list into the MapUsers variable.
// Redirects to the attendance page after successful upload.
//
// Parameters:
//   - res: http.ResponseWriter - the response writer to write the
//     generated HTML content.
//   - req: *http.Request - the incoming HTTP request.
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

		// Check if the headers in the uploaded CSV file are correct
		if err := checkCSVHeaders(savePath, []string{"Student ID", "Name"}); err != nil {
			os.Remove("./students.csv")
			log.Println("Incorrect CSV header:", err)
			http.Error(res, "Incorrect CSV header. Make sure it matches Student ID and Name", http.StatusBadRequest)
			return
		}

		LoadStudentsFromCSV("students.csv")

		http.Redirect(res, req, "/attendance", http.StatusSeeOther)
		return
	}
}

// checkCSVHeaders checks if the headers in the CSV file match the expected headers.
func checkCSVHeaders(filePath string, expectedHeaders []string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	actualHeaders, err := reader.Read()
	if err != nil {
		return err
	}

	// Check if the headers match the expected format
	if !areHeadersCorrect(actualHeaders, expectedHeaders) {
		return fmt.Errorf("incorrect CSV header format")
	}

	return nil
}

func areHeadersCorrect(actualHeaders, expectedHeaders []string) bool {
	// Check if the length of actual and expected headers is the same
	if len(actualHeaders) != len(expectedHeaders) {
		return false
	}

	// Check if each header matches the expected header
	for i, header := range actualHeaders {
		if strings.TrimSpace(header) != expectedHeaders[i] {
			return false
		}
	}

	return true
}

// LoadStudentsFromCSV reads the student data from a CSV file and loads it into the MapUsers variable.
// It also ensures that each student record has an "Attendance" column and updates the student list CSV file accordingly.
//
// Parameters:
//   - filename: string - the name of the CSV file to load and update.
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

// HashPassword generates a bcrypt hash for the given password.
//
// Parameters:
//   - password: string - the password to hash.
//
// Returns:
//   - []byte - the bcrypt hashed password.
func HashPassword(password string) []byte {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}
	return hashedPassword
}

// Submit handles the submission of attendance for the currently logged-in student.
//
// Parameters:
//   - res: http.ResponseWriter - the response writer.
//   - req: *http.Request - the HTTP request.
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

// Export serves the students.csv file for download with a specified filename based on the current date.
//
// Parameters:
//   - res: http.ResponseWriter - the response writer.
//   - req: *http.Request - the HTTP request.
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

	defer func() {
		if err := os.Remove("./students.csv"); err != nil {
			log.Println("Error deleting students.csv:", err)
		}
	}()
}
