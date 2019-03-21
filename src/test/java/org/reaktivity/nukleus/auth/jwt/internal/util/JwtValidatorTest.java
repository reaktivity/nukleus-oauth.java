/**
 * Copyright 2016-2019 The Reaktivity Project
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
package org.reaktivity.nukleus.auth.jwt.internal.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Queue;
import java.util.function.LongSupplier;

import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.lang.JoseException;
import org.junit.Ignore;
import org.junit.Test;

public class JwtValidatorTest
{
    // Example key from RFC-7515 Appendix A.3
    private static final String EXAMPLE_EC256_KEY = "{\"kty\":\"EC\"," +
        "\"crv\":\"P-256\"," +
        "\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\"," +
        "\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"," +
        "\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"" +
       "}";

    // Example key from RFC-7515 Appendix A.2
    private static final String EXAMPLE_RS256_KEY =
            "{\"kty\":\"RSA\"," +
                    "\"n\":\"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx" +
                         "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs" +
                         "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH" +
                         "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV" +
                         "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8" +
                         "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ\"," +
                    "\"e\":\"AQAB\"," +
                    "\"d\":\"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I" +
                         "jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0" +
                         "BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn" +
                         "439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT" +
                         "CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh" +
                         "BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ\"," +
                    "\"p\":\"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi" +
                         "YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG" +
                         "BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc\"," +
                    "\"q\":\"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa" +
                         "ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA" +
                         "-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc\"," +
                    "\"dp\":\"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q" +
                         "CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb" +
                         "34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0\"," +
                    "\"dq\":\"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa" +
                         "7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky" +
                         "NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU\"," +
                    "\"qi\":\"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o" +
                         "y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU" +
                         "W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U\"" +
                   "}";

    private LongSupplier supplyCurrentTimeMillis = () -> System.currentTimeMillis();

    @Test(expected = JoseException.class)
    public void constructorShouldRejectEmptyKeys() throws Exception
    {
        new JwtValidator("", supplyCurrentTimeMillis);
    }

    @Test(expected = JoseException.class)
    public void constructorShouldRejectKeyFileWithInvalidJSONFormat() throws Exception
    {
        new JwtValidator("{\"keys\":  [ {\"kid\":\"key1\",\"", supplyCurrentTimeMillis);
    }

    @Test(expected = JoseException.class)
    public void constructorShouldRejectKeyFileWithMissingCloseQuoteOnPropertyValue() throws Exception
    {
        new JwtValidator("{\"keys\"" +
            "[" +
             "{\"kid\":\"key1\"," +
               "\"kty\":\"EC\"," +
               "\"crv\":\"P-256\"," +
               "\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU," + // missing " at end of property value
               "\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"" +
               "\"alg\":\"ES256\"}" +
           "]" +
         "}", supplyCurrentTimeMillis);
    }

    @Test(expected = JoseException.class)
    @Ignore("jose4j library is not catching this")
    public void constructorShouldRejectKeyFileWithMissingComma() throws Exception
    {
        new JwtValidator("{\"keys\"" +
            "[" +
             "{\"kid\":\"key1\"," +
               "\"kty\":\"EC\"," +
               "\"crv\":\"P-256\"," +
               "\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\"" + // missing comma at end of line
               "\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"" +
               "\"alg\":\"ES256\"}" +
           "]" +
         "}", supplyCurrentTimeMillis);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorShouldRejectKeyWithMissingKid() throws Exception
    {
        new JwtValidator("{\"keys\": [ {" +
                 "\"kty\":\"EC\"," +
                 "\"crv\":\"P-256\"," +
                 "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\", " +
                 "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\", " +
                 "\"alg\":\"ES256\"" +
                "} ] }",
                supplyCurrentTimeMillis);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorShouldRejectKeyWithMissingAlg() throws Exception
    {
        new JwtValidator("{\"keys\": [ {" +
                "\"kid\":\"key1\"," +
                 "\"kty\":\"EC\"," +
                 "\"crv\":\"P-256\"," +
                 "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\", " +
                 "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\", " +
                "} ] }",
                supplyCurrentTimeMillis);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorShouldRejectKeyWithDuplicateKid() throws Exception
    {
        new JwtValidator("{\"keys\": [ " +
             "{" +
                "\"kid\":\"key1\"," +
                 "\"kty\":\"EC\"," +
                 "\"crv\":\"P-256\"," +
                 "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\", " +
                 "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\", " +
                 "\"alg\":\"ES256\"" +
             "}" +
             "{" +
                 "\"kid\":\"key1\"," +
                 "\"kty\":\"EC\"," +
                  "\"crv\":\"P-256\"," +
                  "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\", " +
                  "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\", " +
                  "\"alg\":\"ES256\"" +
              "}" +
                "] }",
                supplyCurrentTimeMillis);
    }

    @Test
    public void constructorShouldAcceptValidJWKSet() throws Exception
    {
        new JwtValidator("{\"keys\": [ {" +
             "\"kid\":\"key1\"," +
              "\"kty\":\"EC\"," +
              "\"crv\":\"P-256\"," +
              "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\", " +
              "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\", " +
              "\"alg\":\"ES256\"" +
             "} ] }",
             supplyCurrentTimeMillis);
    }

    @Test
    public void constructorShouldAcceptValidJWKFile() throws Exception
    {
        Path keys = Paths.get("target", "nukleus-itests", "auth-jwt", "keys", "keys.jwk");
        new JwtValidator(keys, supplyCurrentTimeMillis);
    }

    @Test
    public void shouldNotValidateExpiredES256SignedJwt() throws Exception
    {
        JwtValidator validator = new JwtValidator("{\"keys\": [ {" +
             "\"kid\":\"key1\"," +
              "\"kty\":\"EC\"," +
              "\"crv\":\"P-256\"," +
              "\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\"," +
              "\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"," +
              "\"alg\":\"ES256\"" +
             "} ] }",
             supplyCurrentTimeMillis);

        String realm = validator.validateAndGetRealm(generateExpiredES256SignedJsonWebToken());
        assertNull(realm);
    }

    @Test
    public void shouldNotValidateUnreadyES256SignedJwt() throws Exception
    {
        JwtValidator validator = new JwtValidator("{\"keys\": [ {" +
             "\"kid\":\"key1\"," +
              "\"kty\":\"EC\"," +
              "\"crv\":\"P-256\"," +
              "\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\"," +
              "\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"," +
              "\"alg\":\"ES256\"" +
             "} ] }",
             supplyCurrentTimeMillis);

        String realm = validator.validateAndGetRealm(generateUnreadyES256SignedJsonWebToken());
        assertNull(realm);
    }

    @Test
    public void shouldNotValidateES256SignedJwtWithUnkownKid() throws Exception
    {
        JwtValidator validator = new JwtValidator("{\"keys\": [ {" +
             "\"kid\":\"oops\"," +
              "\"kty\":\"EC\"," +
              "\"crv\":\"P-256\"," +
              "\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\"," +
              "\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"," +
              "\"alg\":\"ES256\"" +
             "} ] }",
             supplyCurrentTimeMillis);

        String realm = validator.validateAndGetRealm(generateES256SignedJsonWebToken());
        assertNull(realm);
    }

    @Test
    public void shouldNotValidateES256SignedJwtWitoutKid() throws Exception
    {
        JwtValidator validator = new JwtValidator("{\"keys\": [ {" +
             "\"kid\":\"key1\"," +
              "\"kty\":\"EC\"," +
              "\"crv\":\"P-256\"," +
              "\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\"," +
              "\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"," +
              "\"alg\":\"ES256\"" +
             "} ] }",
             supplyCurrentTimeMillis);

        String realm = validator.validateAndGetRealm(generateES256SignedJsonWebTokenWithoutKid());
        assertNull(realm);
    }

    @Test
    public void shouldValidateValidES256SignedJwt() throws Exception
    {
        JwtValidator validator = new JwtValidator("{\"keys\": [ {" +
             "\"kid\":\"key1\"," +
              "\"kty\":\"EC\"," +
              "\"crv\":\"P-256\"," +
              "\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\"," +
              "\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"," +
              "\"alg\":\"ES256\"" +
             "} ] }",
             supplyCurrentTimeMillis);

        String realm = validator.validateAndGetRealm(generateES256SignedJsonWebToken());
        assertEquals("key1", realm);
    }

    @Test
    public void shouldValidateValidRS256SignedJwt() throws Exception
    {
        JwtValidator validator = new JwtValidator("{\"keys\": [ {" +
             "\"kid\":\"key2\"," +
              "\"kty\":\"RSA\"," +
              "\"n\":\"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPME" +
                    "zP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63" +
                    "kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4L" +
                    "T6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ\"," +
              "\"e\":\"AQAB\"," +
              "\"alg\":\"RS256\"" +
             "} ] }",
             supplyCurrentTimeMillis);

        String realm = validator.validateAndGetRealm(generateRS256SignedJsonWebToken());
        assertEquals("key2", realm);
    }

    @Test
    public void shouldReportAllKidsAsRealms() throws Exception
    {
        JwtValidator validator = new JwtValidator("{\"keys\": [ " +
                "{" +
                   "\"kid\":\"key1\"," +
                    "\"kty\":\"EC\"," +
                    "\"crv\":\"P-256\"," +
                    "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\", " +
                    "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\", " +
                    "\"alg\":\"ES256\"" +
                "}" +
                "{" +
                    "\"kid\":\"key2\"," +
                    "\"kty\":\"EC\"," +
                     "\"crv\":\"P-256\"," +
                     "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\", " +
                     "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\", " +
                     "\"alg\":\"ES256\"" +
                 "}" +
                   "] }",
                   supplyCurrentTimeMillis);
        final Queue<String> expectedRealms = new ArrayDeque<String>(Arrays.asList("key1", "key2"));
        validator.forEachRealm(s -> assertTrue(s.equals(expectedRealms.poll())));
    }

    private String generateES256SignedJsonWebToken() throws JoseException
    {
        // Example key from RFC-7515 Appendix A.3
        EllipticCurveJsonWebKey key = (EllipticCurveJsonWebKey) JsonWebKey.Factory.newJwk(EXAMPLE_EC256_KEY);

        JwtClaims claims = new JwtClaims();
        claims.setIssuer("test issuer");
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(key.getPrivateKey());
        jws.setKeyIdHeaderValue("key1");
        jws.setAlgorithmHeaderValue("ES256");
        String jwt = jws.getCompactSerialization();
        jws.setKey(key.getKey());
        // System.out.println(jws.toString() + jws.getPayload());
        // System.out.println("ES256 JWT: " + jwt);
        return jwt;
    }

    private String generateRS256SignedJsonWebToken() throws JoseException
    {
        RsaJsonWebKey key = (RsaJsonWebKey) JsonWebKey.Factory.newJwk(EXAMPLE_RS256_KEY);

        JwtClaims claims = new JwtClaims();
        claims.setIssuer("test issuer");
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(key.getPrivateKey());
        jws.setKeyIdHeaderValue("key2");
        jws.setAlgorithmHeaderValue("RS256");
        String jwt = jws.getCompactSerialization();
        jws.setKey(key.getKey());
        // System.out.println(jws.toString() + jws.getPayload());
        // System.out.println("RS256 JWT: " + jwt);
        return jwt;
    }

    private String generateExpiredES256SignedJsonWebToken() throws JoseException
    {
        // Example key from RFC-7515 Appendix A.3
        EllipticCurveJsonWebKey key = (EllipticCurveJsonWebKey) JsonWebKey.Factory.newJwk(EXAMPLE_EC256_KEY);

        JwtClaims claims = new JwtClaims();
        claims.setIssuer("test issuer");
        Calendar calendar = Calendar.getInstance();
        calendar.set(2017, 3, 30, 0, 0, 0);
        long expiredTime = calendar.getTimeInMillis();
        System.out.println("exp: " + expiredTime);
        System.out.println("Current time millis: " + System.currentTimeMillis());
        claims.setExpirationTime(NumericDate.fromMilliseconds(expiredTime));
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(key.getPrivateKey());
        jws.setKeyIdHeaderValue("key1");
        jws.setAlgorithmHeaderValue("ES256");
        String jwt = jws.getCompactSerialization();
        jws.setKey(key.getKey());
        // System.out.println(jws.toString() + jws.getPayload());
        // System.out.println("ES256 JWT: " + jwt);
        return jwt;
    }

    private String generateUnreadyES256SignedJsonWebToken() throws JoseException
    {
        // Example key from RFC-7515 Appendix A.3
        EllipticCurveJsonWebKey key = (EllipticCurveJsonWebKey) JsonWebKey.Factory.newJwk(EXAMPLE_EC256_KEY);

        JwtClaims claims = new JwtClaims();
        claims.setIssuer("test issuer");
        Calendar calendar = Calendar.getInstance();
        calendar.set(2027, 3, 30, 0, 0, 0);
        long notBeforeTime = calendar.getTimeInMillis();
        claims.setNotBefore(NumericDate.fromMilliseconds(notBeforeTime));
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(key.getPrivateKey());
        jws.setKeyIdHeaderValue("key1");
        jws.setAlgorithmHeaderValue("ES256");
        String jwt = jws.getCompactSerialization();
        jws.setKey(key.getKey());
        // System.out.println(jws.toString() + jws.getPayload());
        // System.out.println("ES256 JWT: " + jwt);
        return jwt;
    }

    private String generateES256SignedJsonWebTokenWithoutKid() throws JoseException
    {
        // Example key from RFC-7515 Appendix A.3
        EllipticCurveJsonWebKey key = (EllipticCurveJsonWebKey) JsonWebKey.Factory.newJwk(EXAMPLE_EC256_KEY);

        JwtClaims claims = new JwtClaims();
        claims.setIssuer("test issuer");
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(key.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        String jwt = jws.getCompactSerialization();
        jws.setKey(key.getKey());
        System.out.println(jws.toString() + jws.getPayload());
        System.out.println("ES256 JWT: " + jwt);
        return jwt;
    }

}
