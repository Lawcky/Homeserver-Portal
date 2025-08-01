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
	store       = sessions.NewCookieStore([]byte("super-secret-key"))

	serviceConf []ServiceRoute
)

type ServiceRoute struct {
	Path   string `yaml:"path"`
	Target string `yaml:"target"`
}

func loadRoutes(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return yaml.NewDecoder(file).Decode(&serviceConf)
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
        tmpl := template.Must(template.ParseFiles("templates/layout.html","templates/login.html"))
        tmpl.Execute(w, map[string]string{"Next": next})
        return
    }

    // POST
    r.ParseForm()
    username := r.Form.Get("username")
    password := r.Form.Get("password")

	fmt.Println("Login attempt: ", username)
    if validateCredentials(username, password) {
        session, _ := store.Get(r, "session")
        session.Values["user"] = username
		session.Values["authenticated"] = true
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

// need rework
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	sess, _ := store.Get(r, "session")
	sess.Values["authenticated"] = false
	sess.Save(r, w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, _ := store.Get(r, "session")
		if auth, ok := sess.Values["authenticated"].(bool); !ok || !auth {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// need to change user management later
func validateCredentials(user, password string) bool {
	const hardcodedUser = "admin"
	const hardcodedHash = "$2a$12$zl814bt85KTGqmb0s/f9Lu4wlrjwcLv/eppixTxIx./4HEdM.t/LW" // 'password'
	if user != hardcodedUser {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hardcodedHash), []byte(password)) == nil
}

func getCurrentUser(r *http.Request) (string) {
    session, err := store.Get(r, "session")
    if err != nil {
        return ""
    }

    if userVal, ok := session.Values["user"].(string); ok {
		return userVal
	}
	
	return ""
}

func isAuthenticated(r *http.Request) (bool) {
    session, err := store.Get(r, "session")
    if err != nil {
        return false
    }

    if authVal, ok := session.Values["authenticated"].(bool); ok {
		fmt.Println(authVal)
		return authVal
	}
	
	return false
}

func fileHandler(w http.ResponseWriter, r *http.Request) {
    authStatus := isAuthenticated(r)
    path := r.URL.Path
	fmt.Println(path, url.QueryEscape(path))
    if strings.HasPrefix(path, "/keys") && !authStatus {
        http.Redirect(w, r, "/login?next=files/"+url.QueryEscape(path), http.StatusFound)
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

		if strings.HasPrefix(path, "/keys") && !authStatus {
			http.Redirect(w, r, "/login?next=files/"+url.QueryEscape(path), http.StatusFound)
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

    files := []struct {
        Name string
        URL  string
    }{}

    for _, entry := range entries {
        files = append(files, struct {
            Name string
            URL  string
        }{
            Name: entry.Name(),
            URL:  path + "/" + entry.Name(),
        })
    }

    tmpl := template.Must(template.ParseFiles("templates/layout.html", "templates/files.html"))
    tmpl.Execute(w, map[string]interface{}{
        "Title": "Files",
        "Path":  path,
        "Files": files,
    })
}



func main() {
	err := loadRoutes("services.yaml")
	if err != nil {
		log.Fatalf("Failed to load service config: %v", err)
	}

	r := mux.NewRouter()

	r.HandleFunc("/login", loginHandler).Methods("GET", "POST")
	r.HandleFunc("/logout", logoutHandler).Methods("GET")
	r.PathPrefix("/files").Handler(http.StripPrefix("/files", http.HandlerFunc(fileHandler)))
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	for _, route := range serviceConf {
		proxy := makeReverseProxy(route.Target)
		r.PathPrefix(route.Path).Handler(authMiddleware(http.StripPrefix(route.Path, proxy)))
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