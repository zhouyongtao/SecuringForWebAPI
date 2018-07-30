﻿using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Asn1.Sec;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography;

namespace ECDSAConsoleApp
{
    class Program
    {
        static void Main(string[] args)
        {
            //const string privateKey = "c711e5080f2b58260fe19741a7913e8301c1128ec8e80b8009406e5047e6e1ef";
            //const string publicKey = "04e33993f0210a4973a94c26667007d1b56fe886e8b3c2afdd66aa9e4937478ad20acfbdc666e3cec3510ce85d40365fc2045e5adb7e675198cf57c6638efa1bdb";

            string privateKey = @"jozaiuPf2wtfzZgUoUMwWmHYH7Hih8R41xD8EOVjKgLid2pCCLU7SgaTn0Eh9LVLjPWrR1G17KVma9ICPGbfuIMdhZtIDedZLKlmCanTdZPWSBL6NdE2yQ3oVv5z9TuAqGV5cD98+uPrMFF5ZvM+nrwrYjy1iMMzf6NDJUJWI";
            string publicKey = @"jozaiuPf2wtfzZgUoUMwWmHYH7Hih8R41xD8EOVjKgLid2pCCLU7SgaTn0Eh9L+VLjPWrR1G17KVma9ICPGbfuIMdhZtIDedZLKlmCanTdZPWSBL6NdE2yQ3oVv5z9/TuAqGV5cD98+uPrMFF5ZvM+nrwrYjy1iMMzf6NDJUJWI=/luTLMBhk8yhvVchlHAYdkbw==";

            var privateECDsa = LoadPrivateKey(FromHexString(privateKey));
            var publicECDsa = LoadPublicKey(FromHexString(publicKey));

            var jwt = CreateSignedJwt(privateECDsa);
            var isValid = VerifySignedJwt(publicECDsa, jwt);

            Console.WriteLine(isValid ? "Valid!" : "Not Valid...");
            Console.ReadKey();
        }
        private static byte[] FromHexString(string hex)
        {
            var numberChars = hex.Length;
            var hexAsBytes = new byte[numberChars / 2];
            for (var i = 0; i < numberChars; i += 2)
                hexAsBytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return hexAsBytes;
        }
        private static bool VerifySignedJwt(ECDsa eCDsa, string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var claimsPrincipal = tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidIssuer = "me",
                ValidAudience = "you",
                IssuerSigningKey = new ECDsaSecurityKey(eCDsa)
            }, out var parsedToken);

            return claimsPrincipal.Identity.IsAuthenticated;
        }

        private static string CreateSignedJwt(ECDsa eCDsa)
        {
            var now = DateTime.UtcNow;
            var tokenHandler = new JwtSecurityTokenHandler();

            var jwtToken = tokenHandler.CreateJwtSecurityToken(
                issuer: "me",
                audience: "you",
                subject: null,
                notBefore: now,
                expires: now.AddMinutes(30),
                issuedAt: now,
                signingCredentials: new SigningCredentials(
                    new ECDsaSecurityKey(eCDsa), SecurityAlgorithms.EcdsaSha256));

            return tokenHandler.WriteToken(jwtToken);
        }
        private static ECDsa LoadPrivateKey(byte[] key)
        {
            var privKeyInt = new Org.BouncyCastle.Math.BigInteger(+1, key);
            var parameters = SecNamedCurves.GetByName("secp256r1");
            var ecPoint = parameters.G.Multiply(privKeyInt);
            var privKeyX = ecPoint.Normalize().XCoord.ToBigInteger().ToByteArrayUnsigned();
            var privKeyY = ecPoint.Normalize().YCoord.ToBigInteger().ToByteArrayUnsigned();

            return ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = privKeyInt.ToByteArrayUnsigned(),
                Q = new ECPoint
                {
                    X = privKeyX,
                    Y = privKeyY
                }
            });
        }
        private static ECDsa LoadPublicKey(byte[] key)
        {
            var pubKeyX = key.Skip(1).Take(32).ToArray();
            var pubKeyY = key.Skip(33).ToArray();
            return ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = pubKeyX,
                    Y = pubKeyY
                }
            });
        }
    }
}
