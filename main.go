// main.go
package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

var (
	store = sessions.NewCookieStore([]byte("super-secret-key"))

	serviceConf  []ServiceRoute
	serviceUsers []UserAccount
)

type ServiceRoute struct {
	Path        string `yaml:"path"`
	Target      string `yaml:"target"`
	DisplayName string `yaml:"display_name"`
	Description string `yaml:"description"`
	Icon        string `yaml:"icon"`
	Need_Auth   bool   `yaml:"need_auth"`
	Is_admin    bool   `yaml:"is_admin"`
}

func loadRoutes(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return yaml.NewDecoder(file).Decode(&serviceConf)
}

type UserAccount struct {
	Username             string `yaml:"username"`
	BcryptHashedPassword string `yaml:"bcrypthashedpassword"`
	Is_admin             bool   `yaml:"is_admin"`
}

func loadUsers(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return yaml.NewDecoder(file).Decode(&serviceUsers)
}

func makeReverseProxy(target string) http.Handler {
	targetURL, err := url.Parse(target)
	if err != nil {
		log.Fatalf("Invalid proxy target: %v", err)
	}
	return httputil.NewSingleHostReverseProxy(targetURL)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		next := r.URL.Query().Get("next")
		tmpl := template.Must(template.ParseFiles("templates/layout.html", "templates/login.html", "templates/footer.html"))
		tmpl.Execute(w, map[string]string{"Next": next})
		return
	}

	// POST
	r.ParseForm()
	username := r.Form.Get("username")
	password := r.Form.Get("password")

	is_ok, is_admin := validateCredentials(username, password)
	if is_ok {
		session, _ := store.Get(r, "session")
		session.Values["user"] = username
		session.Values["authenticated"] = true
		session.Values["is_admin"] = is_admin
		session.Save(r, w)

		next := r.Form.Get("next")
		if next != "" {
			http.Redirect(w, r, next, http.StatusFound)
		} else {
			http.Redirect(w, r, "/", http.StatusFound)
		}
		return
	}

	http.Redirect(w, r, "/login", http.StatusFound)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	sess, _ := store.Get(r, "session")
	sess.Options.MaxAge = -1 //deletes the cookie
	sess.Save(r, w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func portalHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("templates/layout.html", "templates/portal.html", "templates/footer.html"))

	// if a message is present add it to the Message field
	// message is equal to whatever is in the portal-message.txt file
	messageFile := "templates/portal-message.txt"
	messageContent, err := os.ReadFile(messageFile)
	if err != nil {
		log.Printf("Error reading message file: %v", err)
	}

	if !isAuthenticated(r) {
		tmpl.Execute(w, map[string]interface{}{
			"Title":    "Portal",
			"isAdmin":  false,
			"Username": "",
			"Services": serviceConf,
			"Message":  string(messageContent),
		})
	} else {
		username := getUserProperty(r, "Username")
		is_admin := getUserProperty(r, "is_admin")

		tmpl.Execute(w, map[string]interface{}{
			"Title":    "Portal",
			"Is_admin": is_admin,
			"Username": username,
			"Services": serviceConf,
			"Message":  string(messageContent),
		})
	}
}

func isRestrictedPath(path string) (bool, bool) {
	if strings.HasPrefix(path, "/users") || strings.Contains(path, "🔑") {
		fmt.Println("need auth")
		return true, false // need authentication but not admin
	}
	if strings.HasPrefix(path, "/admin") {
		fmt.Println("need admin")
		return true, true // need admin authentication
	}
	fmt.Println("need nothin")
	return false, false
}

func fileHandler(w http.ResponseWriter, r *http.Request) {
	authStatus := isAuthenticated(r)
	path := r.URL.Path
	need_auth, need_admin := isRestrictedPath(path)
	fmt.Println(need_auth && (!need_admin || !authStatus))

	if need_admin && !(getUserProperty(r, "is_admin") == "true") { // need admin access, the user is connect and is not admin
		if !authStatus {
			http.Redirect(w, r, "/login?next=files/"+url.QueryEscape(path), http.StatusFound)
			fmt.Println(1)
			return
		}
		http.Error(w, "You need an admin account to access this page.", http.StatusForbidden)
		fmt.Println(3)
		return
	} else if need_auth && !authStatus { // this just requires user authentication and the user is not logged in
		http.Redirect(w, r, "/login?next=files/"+url.QueryEscape(path), http.StatusFound)
		fmt.Println(1)
		return
	}

	basePath := strings.TrimPrefix(path, "/files")
	fullPath := filepath.Join("files", basePath)

	info, err := os.Stat(fullPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if !info.IsDir() {
		// Serve the file content
		safePath := filepath.Clean(basePath)
		fullPath := filepath.Join("files", safePath)

		if need_admin && !(getUserProperty(r, "is_admin") == "true") { // need admin access, the user is connect and is not admin
			if !authStatus {
				http.Redirect(w, r, "/login?next=files/"+url.QueryEscape(path), http.StatusFound)
				fmt.Println(1)
				return
			}
			http.Error(w, "You need an admin account to access this page.", http.StatusForbidden)
			fmt.Println(3)
			return
		} else if need_auth && !authStatus { // this just requires user authentication and the user is not logged in
			http.Redirect(w, r, "/login?next=files/"+url.QueryEscape(path), http.StatusFound)
			fmt.Println(1)
			return
		} else {
			http.ServeFile(w, r, fullPath)
		}
		return
	}

	// Directory: List contents
	entries, err := os.ReadDir(fullPath)
	if err != nil {
		http.Error(w, "Failed to read directory", http.StatusInternalServerError)
		return
	}

	username := getUserProperty(r, "Username")

	files := []struct {
		Name   string
		URL    string
		RETURN string
		IS_DIR bool
	}{}

	for _, entry := range entries {
		files = append(files, struct {
			Name   string
			URL    string
			RETURN string
			IS_DIR bool
		}{
			Name:   entry.Name(),
			URL:    path + "/" + entry.Name(),
			IS_DIR: entry.IsDir(),
		})
	}

	tmpl := template.Must(template.ParseFiles("templates/layout.html", "templates/files.html", "templates/footer.html"))
	tmpl.Execute(w, map[string]interface{}{
		"Title":    "Files",
		"Username": username,
		"Path":     path,
		"Files":    files,
		"Return":   filepath.Join("/files", path, "../"), //strip the last part of the path, if the last part is /files than put / instead
	})
}

func authMiddleware(next http.Handler, user_admin bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := isAuthenticated(r); !auth {
			dest := url.QueryEscape(r.URL.RequestURI())
			http.Redirect(w, r, "/login?next="+dest, http.StatusFound)
			return
		}
		if user_admin {
			is_admin := getUserProperty(r, "is_admin")
			if is_admin != "true" {
				http.Error(w, "You need an admin account to access this page.", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func validateCredentials(user, password string) (bool, bool) {

	for _, u := range serviceUsers {
		if u.Username == user {
			password_check := bcrypt.CompareHashAndPassword([]byte(u.BcryptHashedPassword), []byte(password)) == nil
			is_admin := u.Is_admin
			return password_check, is_admin
		}
	}
	return false, false
}

func getUserProperty(r *http.Request, property string) string {
	session, err := store.Get(r, "session")
	if err != nil {
		return ""
	}

	is_connected := isAuthenticated(r)
	if !is_connected {
		return ""
	}

	switch property {
	case "Username":
		if userVal, ok := session.Values["user"].(string); ok {
			return userVal
		}
	case "is_admin":
		if isAdminVal, ok := session.Values["is_admin"].(bool); ok {
			if isAdminVal {
				return "true"
			}
		}
	}

	return ""
}

func isAuthenticated(r *http.Request) bool {
	session, err := store.Get(r, "session")
	if err != nil {
		return false
	}

	if authVal, ok := session.Values["authenticated"].(bool); ok {
		return authVal
	}

	return false
}

func main() {
	fmt.Println("Starting the portal")
	err := loadRoutes("services.yaml")
	if err != nil {
		log.Fatalf("Failed to load service config: %v", err)
	}

	err = loadUsers("users.yaml")
	if err != nil {
		log.Fatalf("Failed to load user accounts: %v", err)
	}

	r := mux.NewRouter()

	r.HandleFunc("/", portalHandler).Methods("GET")
	r.HandleFunc("/login", loginHandler).Methods("GET", "POST")
	r.HandleFunc("/logout", logoutHandler).Methods("GET")
	r.PathPrefix("/files").Handler(http.StripPrefix("/files", http.HandlerFunc(fileHandler)))
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	r.HandleFunc("/noaccount", func(w http.ResponseWriter, r *http.Request) {
		tmpl := template.Must(template.ParseFiles("templates/layout.html", "templates/noaccount.html", "templates/footer.html"))
		tmpl.Execute(w, map[string]interface{}{})
	}).Methods("GET")

	// Register the routes from service.yaml
	for _, route := range serviceConf {
		proxy := makeReverseProxy(route.Target)
		if route.Need_Auth || route.Is_admin {

			if route.Is_admin {
				r.PathPrefix(route.Path).Handler(authMiddleware(http.StripPrefix(route.Path, proxy), true)) // this will check if the user is authenticated AND if he is admin
			} else {
				r.PathPrefix(route.Path).Handler(authMiddleware(http.StripPrefix(route.Path, proxy), false)) // this will check if the user is authenticated but not if he is admin
			}
			// When the user's manager will be done add a check for is_admin here

		} else {
			r.PathPrefix(route.Path).Handler(http.StripPrefix(route.Path, proxy))
		}
		log.Printf("Registered route: %s -> %s (Need Auth: %t, Is Admin Only: %t)", route.Path, route.Target, route.Need_Auth, route.Is_admin)
	}

	httpsServer := &http.Server{
		Addr:    ":443",
		Handler: r,
	}

	go func() {
		log.Println("Redirecting HTTP to HTTPS")
		http.ListenAndServe(":80", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
		}))
	}()

	// // temporary fix : (allows service /files to webroot)
	// r.PathPrefix("/").Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// 	path := strings.TrimPrefix(r.URL.Path, "/")
	// 	fullPath := filepath.Join("files", path)
	// 	http.ServeFile(w, r, fullPath)
	// }))

	log.Println("Serving HTTPS on port 443")
	err = httpsServer.ListenAndServeTLS(".certs/fullchain.pem", ".certs/privkey.pem")

	if err != nil {
		log.Fatal(err)
	}
}
