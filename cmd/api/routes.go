package main

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
)

func (app *application) routes() http.Handler {
	r := httprouter.New()
	r.NotFound = http.HandlerFunc(app.notFoundResponse)
	r.MethodNotAllowed = http.HandlerFunc(app.methodNotAllowedResponse)

	r.HandlerFunc(http.MethodGet, "/v1/movies", app.listMoviesHandler)
	r.HandlerFunc(http.MethodGet, "/v1/healthcheck", app.healthcheckHandler)
	r.HandlerFunc(http.MethodPost, "/v1/movies", app.createMovieHandler)
	r.HandlerFunc(http.MethodGet, "/v1/movies/:id", app.showMovieHandler)
	r.HandlerFunc(http.MethodPatch, "/v1/movies/:id", app.updateMovieHandler)
	r.HandlerFunc(http.MethodDelete, "/v1/movies/:id", app.deleteMovieHandler)
	r.HandlerFunc(http.MethodPost, "/v1/users", app.registerUserHandler)
	r.HandlerFunc(http.MethodPut, "/v1/users/activated", app.activateUserHandler)
	r.HandlerFunc(http.MethodPost, "/v1/tokens/authentication", app.createAuthenticationTokenHandler)

	return app.recoverPanic(app.rateLimit(app.authenticate(r)))
}
