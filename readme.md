# Shrew

Very simple OAuth2 compliant authentication server with no permanent data storage.

## Endpoints

### `/request-one-time-password` (POST)

Sends a one time password to a specified email.

#### Input
```
{
    "email": USER_EMAIL_ADDRESS
}
```

#### Output
Nothing

### `/token` (POST)
[RFC6749](https://tools.ietf.org/html/rfc6749) compatible. Supports "password" and "refresh_token" grants.

### `/introspect` (POST)
[RFC7662](https://tools.ietf.org/html/rfc7662) compatible.

### `/logout` (POST)

Removes tokens used to make this request.

### `/delete-data` (POST)

Removes all tokens of currently logged in user.

## Required env variables

- SHREW_MAIL_FROM
- SHREW_MAILGUN_APIKEY
- SHREW_MAILGUN_DOMAIN_NAME