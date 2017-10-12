/**
 * Copyright 2016-2017 The Reaktivity Project
 *
 * The Reaktivity Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package org.reaktivity.auth.jwt.internal.util;

import static org.junit.Assert.assertEquals;

import java.nio.file.Path;
import java.nio.file.Paths;

import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;
import org.junit.Test;

public class JwtValidatorTest
{

    public static final String VALID_JWS_ES256 = "eyJhbGciOiJFUzI1NiJ9." +
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
        "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";

    @Test(expected = JoseException.class)
    public void shouldRejectEmptyKeys() throws Exception
    {
        new JwtValidator("");
    }

    @Test(expected = JoseException.class)
    public void shouldRejectKeyFileWithInvalidJSONFormat() throws Exception
    {
        new JwtValidator("{\"keys\":  [ {\"kid\":\"key1\",\"");
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRejectKeyWithMissingKid() throws Exception
    {
        new JwtValidator("{\"keys\": [ {" +
                 "\"kty\":\"EC\"," +
                 "\"crv\":\"P-256\"," +
                 "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\", " +
                 "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\", " +
                 "\"alg\":\"ES256\"" +
                "} ] }");
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRejectKeyWithMissingAlg() throws Exception
    {
        new JwtValidator("{\"keys\": [ {" +
                "\"kid\":\"key1\"," +
                 "\"kty\":\"EC\"," +
                 "\"crv\":\"P-256\"," +
                 "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\", " +
                 "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\", " +
                "} ] }");
    }

    @Test
    public void shouldAcceptValidJWKSet() throws Exception
    {
        new JwtValidator("{\"keys\": [ {" +
             "\"kid\":\"key1\"," +
              "\"kty\":\"EC\"," +
              "\"crv\":\"P-256\"," +
              "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\", " +
              "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\", " +
              "\"alg\":\"ES256\"" +
             "} ] }");
    }

    @Test
    public void shouldAcceptValidJWKFile() throws Exception
    {
        Path keys = Paths.get("target", "nukleus-itests", "auth-jwt", "keys", "keys.jwk");
        new JwtValidator(keys);
    }

    @Test
    public void shouldValidateValidSignedJwt() throws Exception
    {
        JwtValidator validator = new JwtValidator("{\"keys\": [ {" +
             "\"kid\":\"key1\"," +
              "\"kty\":\"EC\"," +
              "\"crv\":\"P-256\"," +
              "\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\"," +
              "\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"," +
              "\"alg\":\"ES256\"" +
             "} ] }");



        assertEquals("key1", validator.validateAndGetRealm(generateES256SignedJsonWebToken()));
    }

    private String generateES256SignedJsonWebToken() throws JoseException
    {
        // Generates a valid signed JWT using the example key from the JWS Specification (RFC-7515 §A.3.1)

        EllipticCurveJsonWebKey key = (EllipticCurveJsonWebKey) JsonWebKey.Factory.newJwk(
                "{\"kty\":\"EC\"," +
                    "\"crv\":\"P-256\"," +
                    "\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\"," +
                    "\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"," +
                    "\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"" +
                   "}");

//        JwtClaims claims = new JwtClaims();
//        claims.setIssuer("jwt test");
        JsonWebSignature jws = new JsonWebSignature();
//        jws.setPayload(claims.toJson());
        jws.setKey(key.getPrivateKey());
        jws.setKeyIdHeaderValue("key1");
        jws.setAlgorithmHeaderValue("ES256");
        String jwt = jws.getCompactSerialization();
        System.out.println("ES256 JWT: " + jwt);
        return jwt;
    }

}
