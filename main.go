// main.go
package main

import (
	// "crypto/tls"
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
	// "golang.org/x/crypto/acme/autocert"
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
	if r.Method == http.MethodGet {
		tmpl := template.Must(template.ParseFiles("templates/login.html"))
		tmpl.Execute(w, nil)
		return
	}

	r.ParseForm()
	user := r.FormValue("username")
	pass := r.FormValue("password")

	fmt.Println("Login attempt:", user, pass)
	if validateCredentials(user, pass) {
		sess, _ := store.Get(r, "session")
		sess.Values["authenticated"] = true
		sess.Save(r, w)
		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}

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

func validateCredentials(user, password string) bool {
	const hardcodedUser = "admin"
	const hardcodedHash = "$2a$12$zl814bt85KTGqmb0s/f9Lu4wlrjwcLv/eppixTxIx./4HEdM.t/LW" // 'password'
	if user != hardcodedUser {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hardcodedHash), []byte(password)) == nil
}

func fileHandler(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/files")
	fullPath := filepath.Join("files", path)

	// if in /files/keys or subdirectories, require auth
	if strings.HasPrefix(path, "/keys") {
		sess, _ := store.Get(r, "session")
		if auth, ok := sess.Values["authenticated"].(bool); !ok || !auth {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
	}

	http.ServeFile(w, r, fullPath)
}

func main() {
	err := loadRoutes("services.yaml")
	if err != nil {
		log.Fatalf("Failed to load service config: %v", err)
	}

	r := mux.NewRouter()

	r.HandleFunc("/login", loginHandler).Methods("GET", "POST")
	r.HandleFunc("/logout", logoutHandler).Methods("GET")

	r.PathPrefix("/files/").Handler(http.StripPrefix("/files", http.HandlerFunc(fileHandler)))

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