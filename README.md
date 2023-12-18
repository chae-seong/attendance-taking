# Attendance Taking

A web application for students to submit their attendance and for admin to upload and export student list.

Admin has to first upload the `students.csv` file that contains `Student ID` and `Name` of students. The students from the students.csv can then login using their Student ID and default password given by the admin before submitting their attendance. This allows the admin to control when users are able to login and the password can be changed daily (i.e. students have to be in class to know the password).

Admin is able to view the students’ attendance and then proceed to export the students.csv file with the updated attendance. Once the admin exports the file, students are unable to login and hence unable to submit their attendance.

## To run the application:

1. Clone the repo using `git clone <git repo link>`
2. Copy the `.env.example` file using `cp .env.example .env`
3. Replace the placeholder values in `.env` file with your own values
4. `go run main.go` to run the application
5. Go to <http://127.0.0.1:5332> in your browser

## Sample students.csv:

```
Student ID,Name
S01,John Doe
S02,Jane Smith
```

## Documentation:

1. `godoc -http=:8080`
2. Go to <localhost:8080> in your browser

## Project Folder Structure

```
├── README.md
├── go.mod
├── go.sum
├── go.work
├── go.work.sum
├── main.go
└── attendance
    ├── attendance.go
    └── templates
        ├── admin.gohtml
        ├── attendance.gohtml
        ├── index.gohtml
        └── login.gohtml
```
