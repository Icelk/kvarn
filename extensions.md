Kvarn is very extensible. Therefore, several pluggable interfaces (called *extensions*) exist to make integration fast and seamless.

Here are the six **P**s
chronologically ordered from the request's encounters. 

# Prime
This is where you can add cache redirects. If you for example want to load the login page on all priviliged pages, you can test the `Authentication` HTTP header
and from there decide to intercept the request.

# Pre
This is tied to Layer 6. See [routing](routing.md) for more information

# Prepare
Called with URI to capture to a function. Will still get all other extensions applied.

It's programmatically an alternative to reading from the file system. It's also very useful for API's (both REST and GraphQL).

# Present
Here, files can opt in to extensions to manipulate data, such as the template system and `hide` extension.

This type can modify most data in response and will be executed in series.

# Package
*I know the name is a stretch*
Here, you can define headers to add to the final response.

**ToDo**: Can cookies be handled here?
Should `Referer` be part of this or `Options` struct?

# Post
These extensions are called after all data are written to the user. This will almost exclusively be used for HTTP/2 push.

Maybe, it can be used to sync data to a database after the request is written to not block it?
