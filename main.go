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
	"time"
	"crypto/tls"
	"golang.org/x/crypto/acme/autocert"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

var (
	store = sessions.NewCookieStore([]byte("super-secret-key"))
	whitelist = autocert.HostWhitelist("dev.lawcky.net", "affine.lawcky.net")
	serviceConf  []ServiceRoute
	serviceUsers []UserAccount
)

type ServiceRoute struct {
	Path        string `yaml:"path"`
	Domain	  	string `yaml:"domain"` // only used for subdomains, if not keep empty
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

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)

		// Preserve Host header
		// req.Host = targetURL.Host //makes somes apps crash

		// set custom headers
		req.Header.Set("X-Forwarded-Host", req.Host)
		req.Header.Set("X-Real-IP", req.RemoteAddr)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-For", req.RemoteAddr)
		// fmt.Println(req)

		req.Header.Set("Upgrade", req.Header.Get("Upgrade"))
		req.Header.Set("Connection", "Upgrade")
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		// log.Printf("Response Headers from %s:\n%v", target, resp.Header)
		return nil
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("Reverse proxy error: %v", err)
		http.Error(w, "Proxy error", http.StatusBadGateway)
	}

	return proxy
}


func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		next := r.URL.Query().Get("next")
		message := r.URL.Query().Get("message")
		tmpl := template.Must(template.ParseFiles("templates/layout.html", "templates/login.html", "templates/footer.html"))
		if message == "Invalid-credentials" {
			tmpl.Execute(w, map[string]string{
				"Next":    next,
				"Message": "Invalid credentials, please try again.",
			})
		} else {
			tmpl.Execute(w, map[string]string{"Next": next})
		}

		return
	}

	// POST
	r.ParseForm()
	username := r.Form.Get("username")
	password := r.Form.Get("password")

	is_ok, is_admin := validateCredentials(username, password)
	if is_ok {
		session, _ := store.Get(r, "session")
		session.Options.HttpOnly = true
		session.Options.Secure = true
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

	time.Sleep(3 * time.Second) // simulate a delay for failed login attempts
	// invalid credentials
	next := r.Form.Get("next")
	http.Redirect(w, r, "/login?next="+url.QueryEscape(next)+"&message=Invalid-credentials", http.StatusFound)
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
		return true, false // need authentication but not admin
	}
	if strings.HasPrefix(path, "/admin") {
		return true, true // need admin authentication
	}
	return false, false
}

func fileHandler(w http.ResponseWriter, r *http.Request) {
	authStatus := isAuthenticated(r)
	path := r.URL.Path
	need_auth, need_admin := isRestrictedPath(path)

	if need_admin && !(getUserProperty(r, "is_admin") == "true") { // need admin access, the user is connect and is not admin
		if !authStatus {
			http.Redirect(w, r, "/login?next=files/"+url.QueryEscape(path), http.StatusFound)
			return
		}
		http.Error(w, "You need an admin account to access this page.", http.StatusForbidden)
		return
	} else if need_auth && !authStatus { // this just requires user authentication and the user is not logged in
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

		if need_admin && !(getUserProperty(r, "is_admin") == "true") { // need admin access, the user is connect and is not admin
			if !authStatus {
				http.Redirect(w, r, "/login?next=files/"+url.QueryEscape(path), http.StatusFound)
				return
			}
			http.Error(w, "You need an admin account to access this page.", http.StatusForbidden)
			return
		} else if need_auth && !authStatus { // this just requires user authentication and the user is not logged in
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

	// 1) Register domain/path reverse proxies
	for _, route := range serviceConf {
		proxy := makeReverseProxy(route.Target)

		if route.Domain != "" {
			hostRoute := r.Host(route.Domain)

			if route.Path != "" && route.Path != "/" {
				hostRoute = hostRoute.PathPrefix(route.Path)
				proxy = http.StripPrefix(route.Path, proxy)
			}

			if route.Need_Auth || route.Is_admin {
				hostRoute.Handler(authMiddleware(proxy, route.Is_admin))
			} else {
				hostRoute.Handler(proxy)
			}

			log.Printf("Registered domain route: host=%s path=%s -> %s", route.Domain, route.Path, route.Target)
			continue
		}

		// path-based fallback
		if route.Need_Auth || route.Is_admin {
			r.PathPrefix(route.Path).Handler(authMiddleware(http.StripPrefix(route.Path, proxy), route.Is_admin))
		} else {
			r.PathPrefix(route.Path).Handler(http.StripPrefix(route.Path, proxy))
		}

		log.Printf("Registered path route: path=%s -> %s", route.Path, route.Target)
	}

	// 2) Static, files and other specific handlers next
	r.PathPrefix("/files").Handler(http.StripPrefix("/files", http.HandlerFunc(fileHandler)))
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	r.HandleFunc("/noaccount", func(w http.ResponseWriter, r *http.Request) {
		tmpl := template.Must(template.ParseFiles("templates/layout.html", "templates/noaccount.html", "templates/footer.html"))
		tmpl.Execute(w, map[string]interface{}{})
	}).Methods("GET")

	// 3) Portal root/save-all-last
	r.HandleFunc("/", portalHandler).Methods("GET")
	r.HandleFunc("/login", loginHandler).Methods("GET", "POST")
	r.HandleFunc("/logout", logoutHandler).Methods("GET")


	m := &autocert.Manager{
        Prompt:     autocert.AcceptTOS,
        HostPolicy: whitelist,
        Cache:      autocert.DirCache(".certs"),
    }

    httpsServer := &http.Server{
        Addr:      ":443",
        Handler:   r,
        TLSConfig: &tls.Config{GetCertificate: m.GetCertificate},
    }

    go func() {
        log.Println("Starting ACME HTTP challenge handler on :80")
        if err := http.ListenAndServe(":80", m.HTTPHandler(nil)); err != nil {
            log.Fatalf("ACME HTTP server failed: %v", err)
        }
    }()

    log.Println("Serving HTTPS on port 443")
    if err := httpsServer.ListenAndServeTLS("", ""); err != nil {
        log.Fatalf("HTTPS server failed: %v", err)
    }
}
