# nukleus-auth-jwt.java

Configuration

System property "jwt.keys", default "keys.jwk", specifies the name of a file which contains a set of public keys in JWK Set format as defined in RFC-7517. These keys must each have a kid (key identifier parameter) unique within the file. Incoming HTTP requests will be considered authenticated only if they contain a JWT (JSON Web Token) signed by the keyin the key set whose kid parameter is equal to the kid parameter specified in the JWT.
