package jwtMiddleware

import (
  "errors"
  "strings"

  "github.com/gofiber/fiber/v2"
)

type jwtExtractor func(c *fiber.Ctx) (string, error)

// jwtFromHeader returns a function that extracts token from the request header.
func jwtFromHeader(header string, authScheme string) func(c *fiber.Ctx) (string, error) {
  return func(c *fiber.Ctx) (string, error) {
    auth := c.Get(header)
    l := len(authScheme)
    if l == 0 {
      return auth, nil
    }
    if len(auth) > l+1 && strings.EqualFold(auth[:l], authScheme) {
      return auth[l+1:], nil
    }
    return "", errors.New("missing or malformed JWT")
  }
}

// jwtFromQuery returns a function that extracts token from the query string.
func jwtFromQuery(param string) func(c *fiber.Ctx) (string, error) {
  return func(c *fiber.Ctx) (string, error) {
    token := c.Query(param)
    if token == "" {
      return "", errors.New("missing or malformed JWT")
    }
    return token, nil
  }
}

// jwtFromParam returns a function that extracts token from the url param string.
func jwtFromParam(param string) func(c *fiber.Ctx) (string, error) {
  return func(c *fiber.Ctx) (string, error) {
    token := c.Params(param)
    if token == "" {
      return "", errors.New("missing or malformed JWT")
    }
    return token, nil
  }
}

// jwtFromCookie returns a function that extracts token from the named cookie.
func jwtFromCookie(name string) func(c *fiber.Ctx) (string, error) {
  return func(c *fiber.Ctx) (string, error) {
    token := c.Cookies(name)
    if token == "" {
      return "", errors.New("missing or malformed JWT")
    }
    return token, nil
  }
}

// jwtFromForm returns a function that extracts token from the named form.
func jwtFromForm(name string) func(c *fiber.Ctx) (string, error) {
  return func(c *fiber.Ctx) (string, error) {
    token := c.FormValue(name, "")
    if token == "" {
      return "", errors.New("missing or malformed JWT")
    }
    return token, nil
  }
}
