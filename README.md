# nukleus-auth-jwt.java 

JWT (JSON Web Token) authorization nukleus. 

## Configuration

System property "auth.jwt.keys", default value "keys.jwk", specifies the name of a file which contains a set of public keys in JWK Set format as defined in RFC-7517. The file name  must either be absolute or relative to the "home" directory of the auth-jwt nukleus. Each key must have the following parameters:

1. kid (key identifier) unique within the file
2. alg (algorithm) specifying the signing algorithm it is to be used with. 

## How incoming HTTP requests are handled

Incoming HTTP requests will be considered authenticated only if the Authorization header is in the form "Bearer JWT", where JWT represents JSON Web Token obeying the following rules:

1. must be a valid signed JSON Web Token in compact form as defined by RFC 1519 JSON Web Token and RFC 1515 JSON Web Signature
2. must be signed by the key in the key set whose kid parameter is equal to the kid parameter specified in the JWT
2. the "exp" (expires) header, if present, must specify a time later than the current time
3. the "nbf" (not before) header, if present, must specify a time earlier than or equal to the current time
