using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Text.Json;
using System.Security.Claims;

public class GenerateToken
{
    public static string GetTokenReqAccess(string encodedTrack, string clientId, string purposeId, string idToken, string kid, string aud)
    {
        RSA rsa = TokenUtils.ReadPrivateKeyFromPem("pk.priv");  // Legge la chiave privata
        var securityKey = new RsaSecurityKey(rsa);
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);

        // Crea l'oggetto "digest" come stringa JSON
        var digestObject = new
        {
            alg = "SHA256",
            value = encodedTrack
        };
        string digestJson = JsonSerializer.Serialize(digestObject);


        long currentTimeInSecs = TokenUtils.CurrentTimeInSecs();
        long expirationTime = currentTimeInSecs + 30000;

        var claim = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Jti, idToken),
            new Claim("purposeId", purposeId),
            new Claim("digest", digestJson,JsonClaimValueTypes.Json), // Converte l'oggetto digest in stringa JSON
            new Claim(JwtRegisteredClaimNames.Aud, aud),
            new Claim(JwtRegisteredClaimNames.Iss, clientId),
            new Claim(JwtRegisteredClaimNames.Sub, clientId)
        };

        // Crea il payload JWT (corretto)
        var payload = new JwtPayload(
            issuer: null,
            audience: null,
            claims: claim,
            issuedAt: DateTimeOffset.FromUnixTimeSeconds(currentTimeInSecs).UtcDateTime,
            expires: DateTimeOffset.FromUnixTimeSeconds(expirationTime).UtcDateTime,
            notBefore: DateTimeOffset.FromUnixTimeSeconds(currentTimeInSecs).UtcDateTime
        );

        // Crea l'header JWT con "kid"
        var header = new JwtHeader(credentials);
        header["kid"] = kid; // Forza l'inserimento del Key ID nell'header

        // Crea il token JWT
        var token = new JwtSecurityToken(header, payload);

        // Genera il token come stringa
        var tokenHandler = new JwtSecurityTokenHandler();
        return tokenHandler.WriteToken(token);
    }

    public static string GetAgidJwtSignature(string digest, string clientId, string idToken, string aud, string kid)
    {
        RSA rsa = TokenUtils.ReadPrivateKeyFromPem("pk.priv");
        var securityKey = new RsaSecurityKey(rsa);
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);


        long currentTimeInSecs = TokenUtils.CurrentTimeInSecs();
        long expirationTime = currentTimeInSecs + 600000;

        var signedHeaders = new Dictionary<string, string>[]
         {
            new Dictionary<string, string> { { "digest", "SHA-256=" + digest } },
            new Dictionary<string, string> { { "content-type", "application/json" } }
         };

        var claim = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Jti, idToken),
            new Claim(JwtRegisteredClaimNames.Iss, clientId),
            new Claim(JwtRegisteredClaimNames.Sub, clientId),
            new Claim(JwtRegisteredClaimNames.Aud, aud),
            new Claim("signed_headers", JsonSerializer.Serialize(signedHeaders),JsonClaimValueTypes.Json)

        };

        var payload = new JwtPayload(
           issuer: null,
           audience: null,
           claims: claim,
           notBefore: DateTimeOffset.FromUnixTimeSeconds(currentTimeInSecs).UtcDateTime,
           expires: DateTimeOffset.FromUnixTimeSeconds(expirationTime).UtcDateTime,
           issuedAt: DateTimeOffset.FromUnixTimeSeconds(currentTimeInSecs).UtcDateTime
       );


        var header = new JwtHeader(credentials);
        header["kid"] = kid; // Aggiunge il Key ID nell'header

        // Crea il token JWT
        var token = new JwtSecurityToken(header, payload);

        // Genera il token come stringa
        var tokenHandler = new JwtSecurityTokenHandler();
        return tokenHandler.WriteToken(token);
    }

    public static string GetAgidTrackingSignature(string purposeId, string clientId, string idToken, string aud,string kid)
    {
        RSA rsa = TokenUtils.ReadPrivateKeyFromPem("pk.priv");
        var securityKey = new RsaSecurityKey(rsa);
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);


        long currentTimeInSecs = TokenUtils.CurrentTimeInSecs();
        long expirationTime = currentTimeInSecs + 600000;

        var claim = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Jti, idToken),
            new Claim(JwtRegisteredClaimNames.Iss, clientId),
            new Claim(JwtRegisteredClaimNames.Sub, clientId),
            new Claim(JwtRegisteredClaimNames.Aud, aud),
            new Claim("purposeId", purposeId),
           // new Claim("dnonce", "1234567890123"),
            new Claim("userID", "User123"),
            new Claim("userLocation", "26.2.12.23"),
            //new Claim("LoA", "LOA3"),

        };

        var payload = new JwtPayload(
           issuer: null,
           audience: null,
           claims: claim,
           notBefore: DateTimeOffset.FromUnixTimeSeconds(currentTimeInSecs).UtcDateTime,
           expires: DateTimeOffset.FromUnixTimeSeconds(expirationTime).UtcDateTime,
           issuedAt: DateTimeOffset.FromUnixTimeSeconds(currentTimeInSecs).UtcDateTime
       );

        var header = new JwtHeader(credentials);
        header["kid"] = kid; // Aggiunge il Key ID nell'header

        // Crea il token JWT
        var token = new JwtSecurityToken(header, payload);

        // Genera il token come stringa
        var tokenHandler = new JwtSecurityTokenHandler();
        return tokenHandler.WriteToken(token);

    }
}
