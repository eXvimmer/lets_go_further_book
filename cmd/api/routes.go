package main

import (
	"expvar"
	"net/http"

	"github.com/julienschmidt/httprouter"
)

func (app *application) routes() http.Handler {
	r := httprouter.New()
	r.NotFound = http.HandlerFunc(app.notFoundResponse)
	r.MethodNotAllowed = http.HandlerFunc(app.methodNotAllowedResponse)

	r.HandlerFunc(http.MethodGet, "/v1/healthcheck", app.healthcheckHandler)
	r.HandlerFunc(http.MethodGet, "/v1/movies", app.requirePermission("movies:read", app.listMoviesHandler))
	r.HandlerFunc(http.MethodPost, "/v1/movies", app.requirePermission("movies:write", app.createMovieHandler))
	r.HandlerFunc(http.MethodGet, "/v1/movies/:id", app.requirePermission("movies:read", app.showMovieHandler))
	r.HandlerFunc(http.MethodPatch, "/v1/movies/:id",
		app.requirePermission("movies:write", app.updateMovieHandler))
	r.HandlerFunc(http.MethodDelete, "/v1/movies/:id",
		app.requirePermission("movies:write", app.deleteMovieHandler))
	r.HandlerFunc(http.MethodPost, "/v1/users", app.registerUserHandler)
	r.HandlerFunc(http.MethodPut, "/v1/users/activated", app.activateUserHandler)
	r.HandlerFunc(http.MethodPost, "/v1/tokens/authentication", app.createAuthenticationTokenHandler)
	r.Handler(http.MethodGet, "/debug/vars", expvar.Handler())

	return app.metrics(app.recoverPanic(app.enableCORS(app.rateLimit(app.authenticate(r)))))
}
