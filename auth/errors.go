package auth

import (
	"errors"
	"net/mail"
)

type InvalidEmailError struct {
	error
}

type EmailOrPasswordInvalidError struct {
	error
}

func newEmailOrPasswordInvalid(email mail.Address) error {
	return EmailOrPasswordInvalidError{errors.New("email and password invalid")}
}

type InvalidTokenError struct {
	error
}

func newInvalidTokenError(token string) error {
	return InvalidTokenError{errors.New("invalid token")}
}
