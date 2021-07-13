Kvarn is very extensible. Therefore, several pluggable interfaces (called *extensions*) exist to make integration fast and seamless.

Here are the five **P**s
chronologically ordered from the request's perspective. 

# Prime

- [ ] Not cached

This is where you can add cache redirects. If you for example want to load the login page on all privileged pages (when the user is not logged in),
you can test the `Authentication` HTTP header
and from there decide to intercept the request.

It is also here where all http requests are upgraded to HTTPS, by redirecting the request to 
a special page where a 307 Redirect is created and returned.

# Prepare

- [x] First response can be cached. The optional `Future` is not.

Called with URI to capture to a function. Will still get all other extensions applied.

It's programmatically an alternative to reading from the file system. It's also very useful for API's (both REST and GraphQL).

# Present

- [x] Cached

Here, files can opt in to extensions to manipulate data, such as the template system and `hide` extension.

This type can modify most data in response and will be executed in series.

# Package

- [ ] Not cached

> *I know the name is a stretch*

Here, you can define headers to add to the final response.
These headers are not cached, but applied every time. You can therefore compare things like other headers and version from request.

Cookies can be defined here, since they won't be cached then.

# Post

- [ ] Not cached

These extensions are called after all data are written to the user. This will almost exclusively be used for HTTP/2 push.

Maybe, it can be used to sync data to a database after the request is written to not block it?
