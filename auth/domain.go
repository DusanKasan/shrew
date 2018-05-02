package auth

import (
	"errors"
	"net/mail"
	"time"
)

type (
	User struct {
		Email   mail.Address
		Subject string
	}

	OneTimePassword struct {
		Subject    string
		Password   string
		Expiration time.Time
	}

	Tokens struct {
		Subject                string
		AccessToken            string
		AccessTokenExpiration  time.Time
		RefreshToken           string
		RefreshTokenExpiration time.Time
	}

	Introspection struct {
		User          User
		Expiration    time.Time
		IsAccessToken bool
	}
)

func RequestOneTimePassword(
	findOrCreateUser func(mail.Address) (User, error),
	createOneTimePassword func(subject string) (OneTimePassword, error),
	sendOneTimePassword func(email mail.Address, otp OneTimePassword) error,
	emailAddress string,
) error {
	email, err := parseEmailAddress(emailAddress)
	if err != nil {
		return InvalidEmailError{err}
	}

	user, err := findOrCreateUser(email)
	if err != nil {
		return errors.New("unable to get user by email: " + err.Error())

	}

	otp, err := createOneTimePassword(user.Subject)
	if err != nil {
		return errors.New("unable to create one time password: " + err.Error())
	}

	if err := sendOneTimePassword(user.Email, otp); err != nil {
		return errors.New("unable to send otp email: " + err.Error())
	}

	return nil
}

func LogIn(
	getUserByEmail func(mail.Address) (*User, error),
	deleteOneTimePassword func(subject string, otp string) (found bool, err error),
	createTokensForSubject func(subject string) (Tokens, error),
	emailAddress string,
	oneTimePassword string,
) (Tokens, error) {
	email, err := parseEmailAddress(emailAddress)
	if err != nil {
		return Tokens{}, InvalidEmailError{err}
	}

	user, err := getUserByEmail(email)
	switch {
	case err != nil:
		return Tokens{}, errors.New("unable to get user by email: " + err.Error())
	case user == nil:
		return Tokens{}, newEmailOrPasswordInvalid(email)
	}

	found, err := deleteOneTimePassword(user.Subject, oneTimePassword)
	switch {
	case err != nil:
		return Tokens{}, errors.New("unable to delete one time password: " + err.Error())
	case !found:
		return Tokens{}, newEmailOrPasswordInvalid(email)
	}

	tokens, err := createTokensForSubject(user.Subject)
	if err != nil {
		return Tokens{}, errors.New("unable to create tokens: " + err.Error())
	}

	return tokens, nil
}

func IntrospectToken(
	getTokensByAccessOrRefreshToken func(token string) (*Tokens, error),
	getUserBySubject func(string) (User, error),
	token string,
) (Introspection, error) {
	tokens, err := getTokensByAccessOrRefreshToken(token)
	switch {
	case err != nil:
		return Introspection{}, errors.New("unable to get tokens: " + err.Error())
	case tokens == nil:
		return Introspection{}, newInvalidTokenError(token)
	}

	user, err := getUserBySubject(tokens.Subject)
	if err != nil {
		return Introspection{}, errors.New("unable to get user by subject: " + err.Error())
	}

	switch token {
	case tokens.AccessToken:
		return Introspection{
			User:          user,
			Expiration:    tokens.AccessTokenExpiration,
			IsAccessToken: true,
		}, nil
	case tokens.RefreshToken:
		return Introspection{
			User:          user,
			Expiration:    tokens.RefreshTokenExpiration,
			IsAccessToken: false,
		}, nil
	default:
		return Introspection{}, errors.New("tokens don't match")
	}
}

func RefreshToken(
	deleteTokensByRefreshToken func(token string) (*Tokens, error),
	getUserBySubject func(string) (User, error),
	createTokensForSubject func(subject string) (Tokens, error),
	refreshToken string,
) (Tokens, error) {
	oldTokens, err := deleteTokensByRefreshToken(refreshToken)
	switch {
	case err != nil:
		return Tokens{}, errors.New("unable to delete oldTokens: " + err.Error())
	case oldTokens == nil,
		oldTokens.RefreshTokenExpiration.Before(time.Now()):
		return Tokens{}, newInvalidTokenError(refreshToken)
	}

	user, err := getUserBySubject(oldTokens.Subject)
	if err != nil {
		return Tokens{}, errors.New("unable to get user by subject: " + err.Error())
	}

	newTokens, err := createTokensForSubject(user.Subject)
	if err != nil {
		return Tokens{}, errors.New("unable to create newTokens: " + err.Error())
	}

	return newTokens, nil
}

func LogOut(
	deleteTokensByAccessToken func(token string) (*Tokens, error),
	accessToken string,
) error {
	oldTokens, err := deleteTokensByAccessToken(accessToken)
	switch {
	case err != nil:
		return errors.New("unable to delete tokens: " + err.Error())
	case oldTokens == nil,
		oldTokens.AccessTokenExpiration.Before(time.Now()):
		return newInvalidTokenError(accessToken)
	default:
		return nil
	}
}

func DeleteUser(
	getTokensByAccessToken func(accessToken string) (*Tokens, error),
	deleteUserBySubject func(accessToken string) error,
	deleteAllTokensBySubject func(accessToken string) error,
	accessToken string,
) error {
	tokens, err := getTokensByAccessToken(accessToken)
	switch {
	case err != nil:
		return errors.New("unable to delete tokens: " + err.Error())
	case tokens == nil,
		tokens.AccessTokenExpiration.Before(time.Now()):
		return newInvalidTokenError(accessToken)
	}

	err = deleteAllTokensBySubject(tokens.Subject)
	if err != nil {
		return errors.New("unable to delete tokens by subject: " + err.Error())
	}

	err = deleteUserBySubject(tokens.Subject)
	if err != nil {
		return errors.New("unable to delete user by subject: " + err.Error())
	}

	return nil
}

func LogOutEverywhere(
	getTokensByAccessToken func(accessToken string) (*Tokens, error),
	deleteAllTokensBySubject func(subject string) error,
	accessToken string,
) error {
	tokens, err := getTokensByAccessToken(accessToken)
	switch {
	case err != nil:
		return errors.New("unable to delete tokens: " + err.Error())
	case tokens == nil,
		tokens.AccessTokenExpiration.Before(time.Now()):
		return newInvalidTokenError(accessToken)
	}

	err = deleteAllTokensBySubject(tokens.Subject)
	if err != nil {
		return errors.New("unable to delete tokens by subject: " + err.Error())
	}

	return nil
}

func parseEmailAddress(email string) (mail.Address, error) {
	m, err := mail.ParseAddress(email)
	switch {
	case err != nil:
		return mail.Address{}, errors.New("invalid Email Address format: " + err.Error())
	case m.Name != "":
		return mail.Address{}, errors.New("invalid Email Address format")
	}

	return *m, nil
}
