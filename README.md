# Attendance Taking

A simple web application for students to submit their attendance and for admin to upload and export student list.

## To run the application:

1. Clone the repo using `git clone <git repo link>`
2. Copy the `.env.example` file using `cp .env.example .env`
3. Replace the placeholder values in `.env` file with your own values
4. `go run main.go` to run the application
5. Go to <http://127.0.0.1:5332> in your browser

## Documentation:

1. `godoc -http=:8080`
2. Go to <localhost:8080> in your browser

## Project Organization

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
