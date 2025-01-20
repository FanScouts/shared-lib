package httpchi

import (
	"context"
	"net/http"
	"strings"
)

func BearerAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Check if the header starts with "Bearer "
		if strings.HasPrefix(authHeader, "Bearer ") {
			// Extract the token by removing the "Bearer " prefix
			token := authHeader[7:]
			// Attach token to context or pass it directly to the next handler
			ctx := context.WithValue(r.Context(), "token", token)
			r = r.WithContext(ctx)
		} else {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Call next handler
		next.ServeHTTP(w, r)
	})
}
