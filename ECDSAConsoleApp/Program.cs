using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Asn1.Sec;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography;
using System.IO;
using System.Text;
using System.Security.Cryptography.X509Certificates;

namespace ECDSAConsoleApp
{
    class Program
    {
        static void Main(string[] args)
        {
            //获得证书文件
            var filePath = Path.Combine(AppContext.BaseDirectory, "Certs\\ecdas.pfx");
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException("Signing Certificate is missing!");
            }
            var x509Cert = new X509Certificate2(filePath, "123456");
            var data = new byte[] { 21, 5, 8, 12, 207 };

            //test signature
            var signature = ECDsaSignData(x509Cert, data);
            Console.WriteLine(ECDsaVerifyData(x509Cert, data, signature) ? "Valid!" : "Not Valid...");

            //test certs signature jwt(openssl)
            var jwtToken = CreateSignedJwt(x509Cert.GetECDsaPrivateKey());
            Console.WriteLine(VerifySignedJwt(x509Cert.GetECDsaPublicKey(), jwtToken) ? "Valid!" : "Not Valid...");

            //test certs signature jwt by BouncyCastle
            string privateKey = "c711e5080f2b58260fe19741a7913e8301c1128ec8e80b8009406e5047e6e1ef";
            string publicKey = "04e33993f0210a4973a94c26667007d1b56fe886e8b3c2afdd66aa9e4937478ad20acfbdc666e3cec3510ce85d40365fc2045e5adb7e675198cf57c6638efa1bdb";
            var privateECDsa = LoadPrivateKey(FromHexString(privateKey));
            var publicECDsa = LoadPublicKey(FromHexString(publicKey));
            var jwt = CreateSignedJwt(privateECDsa);
            var isValid = VerifySignedJwt(publicECDsa, jwt);
            Console.WriteLine(isValid ? "Valid!" : "Not Valid...");

            //test certs signature jwt by Create Private-Public Key pair(https://github.com/smuthiya/EcdsaJwtSigning/blob/master/Program.cs)
            var key = CngKey.Create(CngAlgorithm.ECDsaP256, "ECDsaKey", new CngKeyCreationParameters
            {
                KeyCreationOptions = CngKeyCreationOptions.OverwriteExistingKey,
                KeyUsage = CngKeyUsages.AllUsages,
                ExportPolicy = CngExportPolicies.AllowPlaintextExport
            });
            var cngKey_privateKey = new ECDsaCng(CngKey.Import(key.Export(CngKeyBlobFormat.EccPrivateBlob), CngKeyBlobFormat.EccPrivateBlob));
            cngKey_privateKey.HashAlgorithm = CngAlgorithm.ECDsaP256;
            var cngKey_publicKey = new ECDsaCng(CngKey.Import(key.Export(CngKeyBlobFormat.EccPublicBlob), CngKeyBlobFormat.EccPublicBlob));
            cngKey_publicKey.HashAlgorithm = CngAlgorithm.ECDsaP256;
            var jwt_sign = CreateSignedJwt(privateECDsa);
            Console.WriteLine(VerifySignedJwt(publicECDsa, jwt_sign) ? "Valid!" : "Not Valid...");
            Console.ReadKey();
        }

        private static byte[] ECDsaSignData(X509Certificate2 cert, byte[] data)
        {
            using (ECDsa ecdsa = cert.GetECDsaPrivateKey())
            {
                if (ecdsa == null)
                    throw new ArgumentException("Cert must have an ECDSA private key", nameof(cert));
                return ecdsa.SignData(data, HashAlgorithmName.SHA256);
            }
        }

        private static bool ECDsaVerifyData(X509Certificate2 cert, byte[] data, byte[] signature)
        {
            using (ECDsa ecdsa = cert.GetECDsaPublicKey())
            {
                if (ecdsa == null)
                    throw new ArgumentException("Cert must be an ECDSA cert", nameof(cert));
                return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
            }
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
                signingCredentials: new SigningCredentials(new ECDsaSecurityKey(eCDsa), SecurityAlgorithms.EcdsaSha256));
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
