package introspect

import (
	"net/http"

	introspection "github.com/arsmn/oauth2-introspection"
)

// Config holds the configuration for the middleware
type Config struct {
	introspection.Config

	// AuthScheme is the scheme of Authorization header.
	// Optional. Default: "Bearer"
	AuthScheme string

	// TokenLookup is a function that is used to look up token.
	// Optional. Default: TokenFromHeader
	TokenLookup func(*http.Request) string

	// Unauthorized defines the response body for unauthorized responses.
	// Optional. Default: func(c *http.Request) string { c.SendStatus(401) }
	Unauthorized http.HandlerFunc

	// Forbidden defines the response body for forbidden responses.
	// Optional. Default: func(c *http.Request) string { c.SendStatus(403) }
	Forbidden http.HandlerFunc

	// ErrorHandler is a function for handling unexpected errors.
	// Optional. Default: func(c *http.Request, err error) string { c.SendStatus(500) }
	ErrorHandler func(http.ResponseWriter, *http.Request, error)

	// SuccessHandler defines a function which is executed for a valid token.
	// Optional. Default: nil
	SuccessHandler http.HandlerFunc

	// Filter defines a function to skip middleware.
	// Optional. Default: nil
	Filter func(http.ResponseWriter, *http.Request) bool
}

type Introspection struct {
	config              Config
	oauth2Introspection *introspection.OAuth2Introspection
}

// New creates an introspection middleware for use in Fiber
func New(config ...Config) *Introspection {

	var cfg Config
	if len(config) > 0 {
		cfg = config[0]
	}

	if cfg.AuthScheme == "" {
		cfg.AuthScheme = "Bearer"
	}

	if cfg.Unauthorized == nil {
		cfg.Unauthorized = func(w http.ResponseWriter, r *http.Request) {
			http.Error(w,
				http.StatusText(http.StatusUnauthorized),
				http.StatusUnauthorized)
		}
	}

	if cfg.Forbidden == nil {
		cfg.Forbidden = func(w http.ResponseWriter, r *http.Request) {
			http.Error(w,
				http.StatusText(http.StatusForbidden),
				http.StatusForbidden)
		}
	}

	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w,
				http.StatusText(http.StatusInternalServerError),
				http.StatusInternalServerError)
		}
	}

	if cfg.TokenLookup == nil {
		cfg.TokenLookup = TokenFromHeader("Authorization", cfg.AuthScheme)
	}

	return &Introspection{
		config:              cfg,
		oauth2Introspection: introspection.New(cfg.Config),
	}
}

func (i *Introspection) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if i.config.Filter != nil && i.config.Filter(w, r) {
			h.ServeHTTP(w, r)
			return
		}

		token := i.config.TokenLookup(r)
		result, err := i.oauth2Introspection.Introspect(token)
		if err != nil {
			switch err {
			case introspection.ErrUnauthorized:
				i.config.Unauthorized(w, r)
			case introspection.ErrForbidden:
				i.config.Forbidden(w, r)
			default:
				i.config.ErrorHandler(w, r, err)
			}
			return
		}

		ctx := introspection.WithValue(r.Context(), result)
		r = r.WithContext(ctx)

		h.ServeHTTP(w, r)
	})
}

// TokenFromHeader returns a function that extracts token from the request header.
func TokenFromHeader(header string, authScheme string) func(*http.Request) string {
	return func(r *http.Request) string {
		auth := r.Header.Get(header)
		l := len(authScheme)
		if len(auth) > l+1 && auth[:l] == authScheme {
			return auth[l+1:]
		}
		return ""
	}
}

// TokenFromQuery returns a function that extracts token from the query string.
func TokenFromQuery(param string) func(*http.Request) string {
	return func(r *http.Request) string {
		return r.URL.Query().Get(param)
	}
}

// TokenFromCookie returns a function that extracts token from the named cookie.
func TokenFromCookie(name string) func(*http.Request) string {
	return func(r *http.Request) string {
		cookie, _ := r.Cookie(name)
		return cookie.Value
	}
}
