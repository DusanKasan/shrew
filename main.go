package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"net/mail"
	"os"
	"strings"
	"sync"
	"time"

	"fmt"

	"github.com/DusanKasan/shrew/auth"
)

type repository struct {
	mux    sync.Mutex
	users  []auth.User
	otps   []auth.OneTimePassword
	tokens []auth.Tokens
}

func (r *repository) CreateUser(user auth.User) (alreadyRegistered bool, err error) {
	r.mux.Lock()
	for _, u := range r.users {
		if u.Email == user.Email {
			r.mux.Unlock()
			return true, nil
		}
	}

	r.users = append(r.users, user)
	r.mux.Unlock()
	return false, nil
}

func (r *repository) CreateOneTimePassword(subject string) (auth.OneTimePassword, error) {
	pass, err := generateRandomString(8)
	if err != nil {
		return auth.OneTimePassword{}, err
	}

	otp := auth.OneTimePassword{
		Subject:    subject,
		Expiration: time.Now().Add(time.Hour),
		Password:   pass,
	}

	r.mux.Lock()
	r.otps = append(r.otps, otp)
	r.mux.Unlock()
	return otp, nil
}

func (r *repository) DeleteOneTimePassword(subject string, otp string) (found bool, err error) {
	r.mux.Lock()
	for i, o := range r.otps {
		if o.Subject == subject && o.Password == otp {
			r.otps = append(r.otps[:i], r.otps[i+1:]...)
			r.mux.Unlock()
			return true, nil
		}
	}

	r.mux.Unlock()
	return false, nil
}

func (r *repository) FindOrCreateUser(email mail.Address) (auth.User, error) {
	r.mux.Lock()
	for _, u := range r.users {
		if u.Email == email {
			r.mux.Unlock()
			return u, nil
		}
	}

	user := auth.User{Email: email, Subject: email.Address}
	r.users = append(r.users, user)
	r.mux.Unlock()

	return user, nil
}

func (r *repository) GetUserByEmail(email mail.Address) (*auth.User, error) {
	r.mux.Lock()
	for _, u := range r.users {
		if u.Email == email {
			r.mux.Unlock()
			return &u, nil
		}
	}
	r.mux.Unlock()
	return nil, nil
}

func (r *repository) GetUserBySubject(subject string) (auth.User, error) {
	r.mux.Lock()
	for _, u := range r.users {
		if u.Subject == subject {
			r.mux.Unlock()
			return u, nil
		}
	}

	r.mux.Unlock()
	return auth.User{}, errors.New("unable to find user")
}

func (r *repository) CreateTokensForSubject(subject string) (auth.Tokens, error) {
	accessToken, err := generateRandomString(32)
	if err != nil {
		return auth.Tokens{}, err
	}

	refreshToken, err := generateRandomString(32)
	if err != nil {
		return auth.Tokens{}, err
	}

	tokens := auth.Tokens{
		Subject:                subject,
		AccessToken:            accessToken,
		AccessTokenExpiration:  time.Now().Add(time.Hour),
		RefreshToken:           refreshToken,
		RefreshTokenExpiration: time.Now().Add(time.Hour * 24 * 30 * 12),
	}

	r.mux.Lock()
	r.tokens = append(r.tokens, tokens)
	r.mux.Unlock()

	return tokens, nil
}

func (r *repository) DeleteTokensByRefreshToken(token string) (*auth.Tokens, error) {
	r.mux.Lock()
	for i, t := range r.tokens {
		if t.RefreshToken == token {
			r.tokens = append(r.tokens[:i], r.tokens[i+1:]...)
			r.mux.Unlock()
			return &t, nil
		}
	}

	r.mux.Unlock()
	return nil, nil
}

func (r *repository) GetTokensByAccessOrRefreshToken(token string) (*auth.Tokens, error) {
	r.mux.Lock()
	for _, t := range r.tokens {
		if t.RefreshToken == token || t.AccessToken == token {
			r.mux.Unlock()
			return &t, nil
		}
	}

	r.mux.Unlock()
	return nil, nil
}

func (r *repository) GetTokensByAccessToken(token string) (*auth.Tokens, error) {
	r.mux.Lock()
	for _, t := range r.tokens {
		if t.AccessToken == token {
			r.mux.Unlock()
			return &t, nil
		}
	}

	r.mux.Unlock()
	return nil, nil
}

func (r *repository) DeleteTokensByAccessToken(token string) (*auth.Tokens, error) {
	r.mux.Lock()
	for i, t := range r.tokens {
		if t.AccessToken == token {
			r.tokens = append(r.tokens[:i], r.tokens[i+1:]...)
			r.mux.Unlock()
			return &t, nil
		}
	}

	r.mux.Unlock()
	return nil, nil
}

func (r *repository) DeleteAllTokensBySubject(subject string) error {
	r.mux.Lock()
	var tokens []auth.Tokens
	for _, t := range r.tokens {
		if t.Subject != subject {
			tokens = append(tokens, t)
		}
	}

	r.tokens = tokens
	r.mux.Unlock()
	return nil
}

func (r *repository) DeleteUserBySubject(subject string) error {
	r.mux.Lock()
	for i, u := range r.users {
		if u.Subject == subject {
			r.users = append(r.users[:i], r.users[i+1:]...)
			r.mux.Unlock()
			return nil
		}
	}

	r.mux.Unlock()
	return nil
}

type mailer struct {
	apiKey     string
	domainName string
	from       mail.Address
}

func (m *mailer) OneTimePassword(email mail.Address, otp auth.OneTimePassword) error {
	client := &http.Client{}

	var buff bytes.Buffer
	w := multipart.NewWriter(&buff)

	fw, err := w.CreateFormField("from")
	if err != nil {
		return err
	}
	fw.Write([]byte(m.from.String()))

	fw, err = w.CreateFormField("to")
	if err != nil {
		return err
	}
	fw.Write([]byte(email.String()))

	fw, err = w.CreateFormField("subject")
	if err != nil {
		return err
	}
	fw.Write([]byte("OTP"))

	fw, err = w.CreateFormField("text")
	if err != nil {
		return err
	}
	fw.Write([]byte(otp.Password))

	w.Close()

	req, err := http.NewRequest("POST", "https://api.mailgun.net/v3/"+m.domainName+"/messages", &buff)
	if err != nil {
		return err
	}
	req.SetBasicAuth("api", m.apiKey)
	req.Header.Set("Content-Type", w.FormDataContentType())

	resp, err := client.Do(req)
	switch {
	case err != nil:
		return err
	case resp.StatusCode != http.StatusOK:
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return errors.New(fmt.Sprintf("Invalid status returned %v %v", resp.StatusCode, string(body)))
	}

	return nil
}

func main() {
	mailFrom := os.Getenv("SHREW_MAIL_FROM")
	mailgunAPIkey := os.Getenv("SHREW_MAILGUN_APIKEY")
	mailgunDomainName := os.Getenv("SHREW_MAILGUN_DOMAIN_NAME")

	if mailFrom == "" || mailgunAPIkey == "" || mailgunDomainName == "" {
		panic("Environment variables not present")
	}

	u := &repository{}
	m := &mailer{
		from:       mail.Address{Name: "", Address: mailFrom},
		apiKey:     mailgunAPIkey,
		domainName: mailgunDomainName,
	}

	http.HandleFunc("/request-one-time-password", func(w http.ResponseWriter, r *http.Request) {
		b, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Print(err)
			return
		}

		var data struct {
			Email string `json:"email"`
		}
		err = json.Unmarshal(b, &data)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid input"))
			log.Print(err)
			return
		}

		err = auth.RequestOneTimePassword(u.FindOrCreateUser, u.CreateOneTimePassword, m.OneTimePassword, data.Email)
		switch err.(type) {
		case nil: // skip
		case auth.InvalidEmailError:
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid email format"))
			log.Print(err)
		default:
			w.WriteHeader(http.StatusInternalServerError)
			log.Print(err)
		}
	})

	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		type response struct {
			AccessToken  string `json:"access_token"`
			ExpiresIn    int64  `json:"expires_in"`
			RefreshToken string `json:"refresh_token"`
			TokenType    string `json:"token_type"`
		}

		var tokens auth.Tokens
		var err error

		switch r.PostFormValue("grant_type") {
		case "password":
			username := r.PostFormValue("username")
			password := r.PostFormValue("password")
			if username == "" || password == "" {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error":"invalid_request"}`))
				return
			}

			tokens, err = auth.LogIn(
				u.GetUserByEmail,
				u.DeleteOneTimePassword,
				u.CreateTokensForSubject,
				username,
				password,
			)
		case "refresh_token":
			refreshToken := r.PostFormValue("refresh_token")
			if refreshToken == "" {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error":"invalid_request"}`))
				return
			}

			tokens, err = auth.RefreshToken(
				u.DeleteTokensByRefreshToken,
				u.GetUserBySubject,
				u.CreateTokensForSubject,
				refreshToken,
			)
		default:
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"unsupported_grant_type"}`))
			return
		}

		switch err.(type) {
		case nil: // skip
		case auth.InvalidEmailError:
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"invalid_request"}`))
			log.Print(err)
			return
		case auth.InvalidTokenError, auth.EmailOrPasswordInvalidError:
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"unauthorized_client"}`))
			log.Print(err)
			return
		default:
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"server_error"}`))
			log.Print(err)
			return
		}

		resp := response{
			tokens.AccessToken,
			int64(tokens.AccessTokenExpiration.Sub(time.Now()) / time.Second),
			tokens.RefreshToken,
			"bearer",
		}

		b, err := json.Marshal(resp)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"server_error"}`))
			log.Print(err)
			return
		}

		w.Write(b)
	})

	http.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		bearerToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if bearerToken == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"access_denied"}`))
			return
		}

		bearerTokenIntrospection, err := auth.IntrospectToken(u.GetTokensByAccessOrRefreshToken, u.GetUserBySubject, bearerToken)
		switch err.(type) {
		case nil: // skip
		case auth.InvalidTokenError:
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"access_denied"}`))
			log.Print(err)
			return
		default:
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"server_error"}`))
			log.Print(err)
			return
		}

		if bearerTokenIntrospection.Expiration.Before(time.Now()) || !bearerTokenIntrospection.IsAccessToken {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"access_denied"}`))
			return
		}

		token := r.PostFormValue("token")
		if token == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"invalid_request"}`))
			return
		}

		introspection, err := auth.IntrospectToken(u.GetTokensByAccessOrRefreshToken, u.GetUserBySubject, token)
		switch err.(type) {
		case nil: // skip
		case auth.InvalidTokenError:
			w.Write([]byte(`{"active":false}`))
			log.Print(err)
			return
		default:
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"server_error"}`))
			log.Print(err)
			return
		}

		resp := struct {
			Active              bool   `json:"active"`
			ExpirationTimestamp int64  `json:"exp"`
			Subject             string `json:"sub"`
		}{
			true,
			introspection.Expiration.Unix(),
			introspection.User.Subject,
		}

		b, err := json.Marshal(resp)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"server_error"}`))
			log.Print(err)
			return
		}

		w.Write(b)
	})

	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		accessToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if accessToken == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		bearerTokenIntrospection, err := auth.IntrospectToken(u.GetTokensByAccessOrRefreshToken, u.GetUserBySubject, accessToken)
		switch err.(type) {
		case nil: // skip
		case auth.InvalidTokenError:
			w.WriteHeader(http.StatusUnauthorized)
			return
		default:
			w.WriteHeader(http.StatusInternalServerError)
			log.Print(err)
			return
		}

		if bearerTokenIntrospection.Expiration.Before(time.Now()) || !bearerTokenIntrospection.IsAccessToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		err = auth.LogOut(u.DeleteTokensByAccessToken, accessToken)
		switch err.(type) {
		case nil: // skip
		case auth.InvalidTokenError:
			w.WriteHeader(http.StatusUnauthorized)
			return
		default:
			w.WriteHeader(http.StatusInternalServerError)
			log.Print(err)
			return
		}
	})

	http.HandleFunc("/delete-data", func(w http.ResponseWriter, r *http.Request) {
		accessToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if accessToken == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		introspection, err := auth.IntrospectToken(u.GetTokensByAccessOrRefreshToken, u.GetUserBySubject, accessToken)
		switch err.(type) {
		case nil: // skip
		case auth.InvalidTokenError:
			w.WriteHeader(http.StatusUnauthorized)
			return
		default:
			w.WriteHeader(http.StatusInternalServerError)
			log.Print(err)
			return
		}

		if introspection.Expiration.Before(time.Now()) || !introspection.IsAccessToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		err = auth.DeleteUser(
			u.GetTokensByAccessToken,
			u.DeleteUserBySubject,
			u.DeleteAllTokensBySubject,
			introspection.User.Subject,
		)
		switch err.(type) {
		case nil: // skip
		case auth.InvalidTokenError:
			w.WriteHeader(http.StatusUnauthorized)
			return
		default:
			w.WriteHeader(http.StatusInternalServerError)
			log.Print(err)
			return
		}
	})

	if err := http.ListenAndServe(":8081", nil); err != nil {
		panic(err)
	}
}

func generateRandomString(length int) (string, error) {
	var letter = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	for i, v := range b {
		b[i] = letter[int(v)%len(letter)]
	}
	return string(b), err
}
