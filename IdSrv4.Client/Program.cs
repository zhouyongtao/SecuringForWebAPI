using IdentityModel;
using IdentityModel.Client;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography;

namespace IdSrv4.Client
{
    class Program
    {
        static void Main(string[] args)
        {
            Task.Run(() =>
            {
                return Run();
            });
            Console.ReadLine();
        }

        public static async Task Run()
        {
            try
            {
                //https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/blob/master/test/System.IdentityModel.Tokens.Jwt.Tests/CreateAndValidateTokens.cs
                //https://jwt.io
                //获得证书文件
                var filePath = Path.Combine(AppContext.BaseDirectory, "Certs\\idsrv4.pfx");
                if (!File.Exists(filePath))
                {
                    throw new FileNotFoundException("Signing Certificate is missing!");
                }
                var credential = new SigningCredentials(new X509SecurityKey(new X509Certificate2(filePath, "123456")), "RS256");
                if (credential == null)
                {
                    throw new InvalidOperationException("No signing credential is configured. Can't create JWT token");
                }
                var header = new JwtHeader(credential);
                // emit x5t claim for backwards compatibility with v4 of MS JWT library
                if (credential.Key is X509SecurityKey x509key)
                {
                    var cert = x509key.Certificate;
                    var pub_key = cert.GetPublicKeyString();
                    header["x5t"] = Base64Url.Encode(cert.GetCertHash());
                }
                var payload = new JwtPayload();
                payload.AddClaims(ClaimSets.DefaultClaims);
                var jwtTokenHandler = new JwtSecurityTokenHandler();
                var jwtToken = jwtTokenHandler.WriteToken(new JwtSecurityToken(header, payload));
                SecurityToken validatedSecurityToken = null;
                //ValidateToken
                var vaild = jwtTokenHandler.ValidateToken(jwtToken, new TokenValidationParameters
                {
                    IssuerSigningKey = credential.Key,
                    RequireExpirationTime = false,
                    RequireSignedTokens = true,
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidateLifetime = false,
                }, out validatedSecurityToken);
                //ReadJwtToken
                var readJwtToken = jwtTokenHandler.ReadJwtToken(jwtToken);
            }
            catch (Exception ex)
            {
            }
            var disco = await DiscoveryClient.GetAsync("http://localhost:5000");
            var client = new TokenClient(disco.TokenEndpoint, "client_credentials_jwt_grant", "123456");
            var response = await client.RequestClientCredentialsAsync("api");
            if (response.IsError)
            {
                Console.WriteLine(response.Error);
                Console.Read();
            }
            Console.WriteLine(response.Json);
            //call api
            var http = new HttpClient();
            http.SetBearerToken(response.AccessToken);
            var message = await http.GetAsync("http://localhost:17181/api/values/1");
            if (!message.IsSuccessStatusCode)
            {
                Console.WriteLine(message.ReasonPhrase);
                Console.Read();
            }
            Console.WriteLine(message.Content.ReadAsStringAsync().Result);
        }
    }

    /// <summary>
    /// Contains a number of different claims sets used to test round tripping claims sets.
    /// </summary>
    public static class ClaimSets
    {
        static ClaimSets()
        {
            DefaultClaims = new List<Claim>
            {
                new Claim("name", "irving", ClaimValueTypes.String, Default.Issuer),
                new Claim(ClaimTypes.Country, "USA", ClaimValueTypes.String, Default.Issuer),
                new Claim(ClaimTypes.NameIdentifier, "Bob", ClaimValueTypes.String, Default.Issuer),
                new Claim(ClaimTypes.Email, "Bob@contoso.com", ClaimValueTypes.String, Default.Issuer),
                new Claim(ClaimTypes.GivenName, "Bob", ClaimValueTypes.String, Default.Issuer),
                new Claim(ClaimTypes.HomePhone, "555.1212", ClaimValueTypes.String, Default.Issuer),
                new Claim(ClaimTypes.Role, "Developer", ClaimValueTypes.String, Default.Issuer),
                new Claim(ClaimTypes.Role, "Sales", ClaimValueTypes.String, Default.Issuer),
                new Claim(ClaimsIdentity.DefaultNameClaimType, "Jean-Sébastien", ClaimValueTypes.String, Default.Issuer),
                new Claim("role", "role1", ClaimValueTypes.String, Default.Issuer),
            };
        }

        public static List<Claim> DefaultClaims
        {
            get;
            private set;
        }
    }

    /// <summary>
    /// Returns default token creation / validation artifacts:
    /// Claim
    /// ClaimIdentity
    /// ClaimPrincipal
    /// SecurityTokenDescriptor
    /// TokenValidationParameters
    /// </summary>
    public static class Default
    {
        public static string ActorIssuer
        {
            get => "http://Default.ActorIssuer.com/Actor";
        }

        public static string Acr
        {
            get => "Default.Acr";
        }

        public static string Amr
        {
            get => "Default.Amr";
        }

        public static List<string> Amrs
        {
            get => new List<string> { "Default.Amr1", "Default.Amr2", "Default.Amr3", "Default.Amr4" };
        }

        public static string AttributeName
        {
            get => "Country";
        }

        public static string AttributeNamespace
        {
            get => "http://schemas.xmlsoap.org/ws/2005/05/identity/claims";
        }

        public static string Audience
        {
            get => "http://Default.Audience.com";
        }

        public static List<string> Audiences
        {
            get
            {
                return new List<string>
                {
                  "http://Default.Audience.com",
                  "http://Default.Audience1.com",
                  "http://Default.Audience2.com",
                  "http://Default.Audience3.com",
                  "http://Default.Audience4.com"
                };
            }
        }

        public static string AuthenticationInstant
        {
            get => "2017-03-18T18:33:37.080Z";
        }

        public static DateTime AuthenticationInstantDateTime
        {
            get => new DateTime(2017, 03, 18, 18, 33, 37, 80, DateTimeKind.Utc);
        }

        public static string AuthenticationMethod
        {
            get => "urn:oasis:names:tc:SAML:1.0:am:password";
        }

        public static Uri AuthenticationMethodUri
        {
            get => new Uri("urn:oasis:names:tc:SAML:1.0:am:password");
        }

        public static string AuthenticationType
        {
            get => "Default.Federation";
        }

        public static string AuthorityKind
        {
            get => "samlp:AttributeQuery";
        }

        public static string AuthorizedParty
        {
            get => "http://relyingparty.azp.com";
        }

        public static string Azp
        {
            get => "http://Default.Azp.com";
        }

        public static string Binding
        {
            get => "http://www.w3.org/";
        }

        public static string CertificateData
        {
            get => "MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD";
        }

        public static List<Claim> Claims
        {
            get => ClaimSets.DefaultClaims;
        }

        public static ClaimsIdentity ClaimsIdentity
        {
            get => new ClaimsIdentity(Claims, AuthenticationType);
        }

        public static string ClaimsIdentityLabel
        {
            get => "Default.ClaimsIdentityLabel";
        }

        public static string ClaimsIdentityLabelDup
        {
            get => "Default.ClaimsIdentityLabelDup";
        }

        public static ClaimsPrincipal ClaimsPrincipal
        {
            get => new ClaimsPrincipal(ClaimsIdentity);
        }

        public static string ClientId
        {
            get => "http://Default.ClientId";
        }

        public static string Country
        {
            get => "USA";
        }

        public static string DNSAddress
        {
            get => "corp.microsoft.com";
        }

        public static string DNSName
        {
            get => "default.dns.name";
        }

        public static DateTime Expires
        {
            get => DateTime.Parse(ExpiresString);
        }


        public static string ExpiresString
        {
            get => "2021-03-17T18:33:37.080Z";
        }

        public static HashAlgorithm HashAlgorithm
        {
            get => SHA256.Create();
        }

        public static string IPAddress
        {
            get => "127.0.0.1";
        }

        public static DateTime IssueInstant
        {
            get => DateTime.Parse(IssueInstantString);
        }

        public static string IssueInstantString
        {
            get => "2017-03-17T18:33:37.095Z";
        }

        public static string Issuer
        {
            get => "http://Default.Issuer.com";
        }

        public static IEnumerable<string> Issuers
        {
            get => new List<string> { Guid.NewGuid().ToString(), "http://Default.Issuer.com", "http://Default.Issuer2.com", "http://Default.Issuer3.com" };
        }

#if !CrossVersionTokenValidation
        public static string Jwt(SecurityTokenDescriptor tokenDescriptor)
        {
            return (new JwtSecurityTokenHandler()).CreateEncodedJwt(tokenDescriptor);
        }
#endif

        public static string Location
        {
            get => "http://www.w3.org/";
        }

        public static string NameClaimType
        {
            get => "Default.NameClaimType";
        }

        public static string NameQualifier
        {
            get => "NameIdentifier";
        }

        public static string NameIdentifierFormat
        {
            get => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
        }

        public static string Nonce
        {
            get => "Default.Nonce";
        }

        public static DateTime NotBefore
        {
            get => DateTime.Parse("2017-03-17T18:33:37.080Z");
        }

        public static string NotBeforeString
        {
            get => "2017-03-17T18:33:37.080Z";
        }

        public static DateTime NotOnOrAfter
        {
            get => DateTime.Parse("2017-03-18T18:33:37.080Z");
        }

        public static string NotOnOrAfterString
        {
            get => "2017-03-18T18:33:37.080Z";
        }

        public static string OriginalIssuer
        {
            get => "http://Default.OriginalIssuer.com";
        }

        public static string OuterXml
        {
            get => "<OuterXml></OuterXml>";
        }

        public static string ReferenceDigestMethod
        {
            get => SecurityAlgorithms.Sha256Digest;
        }
        public static string ReferenceId
        {
            get => "#abcdef";
        }

        public static string ReferencePrefix
        {
            get => "ds";
        }

        public static string ReferenceType
        {
            get => "http://referenceType";
        }

        public static string ReferenceUri
        {
            get => "http://referenceUri";
        }

        public static string RoleClaimType
        {
            get => "Default.RoleClaimType";
        }


        public static string SamlAccessDecision
        {
            get => "Permit";
        }



        public static string SamlAssertionID
        {
            get => "_b95759d0-73ae-4072-a140-567ade10a7ad";
        }

        /// <summary>
        /// SamlClaims require the ability to split into name / namespace
        /// </summary>
        public static List<Claim> SamlClaims
        {
            get => new List<Claim>
            {
                new Claim(ClaimTypes.Country, "USA", ClaimValueTypes.String, Issuer, OriginalIssuer),
                new Claim(ClaimTypes.NameIdentifier, "Bob", ClaimValueTypes.String, Issuer, OriginalIssuer),
                new Claim(ClaimTypes.Email, "Bob@contoso.com", ClaimValueTypes.String, Issuer, OriginalIssuer),
                new Claim(ClaimTypes.GivenName, "Bob", ClaimValueTypes.String, Issuer, OriginalIssuer),
                new Claim(ClaimTypes.HomePhone, "555.1212", ClaimValueTypes.String, Issuer, OriginalIssuer),
                new Claim(ClaimTypes.Role, "Developer", ClaimValueTypes.String, Issuer, OriginalIssuer),
                new Claim(ClaimTypes.Role, "Sales", ClaimValueTypes.String, Issuer, OriginalIssuer),
                new Claim(ClaimTypes.StreetAddress, "123AnyWhereStreet/r/nSomeTown/r/nUSA", ClaimValueTypes.String, Issuer, OriginalIssuer),
                new Claim(ClaimsIdentity.DefaultNameClaimType, "Jean-Sébastien", ClaimValueTypes.String, Issuer, OriginalIssuer),
            };
        }

        /// <summary>
        /// SamlClaims require the ability to split into name / namespace
        /// </summary>
        public static List<Claim> SamlClaimsIssuerEqOriginalIssuer
        {
            get => new List<Claim>
            {
                new Claim(ClaimTypes.Country, "USA", ClaimValueTypes.String, Issuer),
                new Claim(ClaimTypes.NameIdentifier, "Bob", ClaimValueTypes.String, Issuer),
                new Claim(ClaimTypes.Email, "Bob@contoso.com", ClaimValueTypes.String, Issuer),
                new Claim(ClaimTypes.GivenName, "Bob", ClaimValueTypes.String, Issuer),
                new Claim(ClaimTypes.HomePhone, "555.1212", ClaimValueTypes.String, Issuer),
                new Claim(ClaimTypes.Role, "Developer", ClaimValueTypes.String, Issuer),
                new Claim(ClaimTypes.Role, "Sales", ClaimValueTypes.String, Issuer),
                new Claim(ClaimTypes.StreetAddress, "123AnyWhereStreet/r/nSomeTown/r/nUSA", ClaimValueTypes.String, Issuer),
                new Claim(ClaimsIdentity.DefaultNameClaimType, "Jean-Sébastien", ClaimValueTypes.String, Issuer),
            };
        }

        public static ClaimsIdentity SamlClaimsIdentity
        {
            get => new ClaimsIdentity(SamlClaims, AuthenticationType);
        }



        public static string SamlConfirmationData
        {
            get => "ConfirmationData";
        }

        public static string SamlConfirmationMethod
        {
            get => "urn:oasis:names:tc:SAML:1.0:cm:bearer";
        }

        public static string SamlResource
        {
            get => "http://www.w3.org/";
        }


        public static SecurityTokenDescriptor SecurityTokenDescriptor(EncryptingCredentials encryptingCredentials)
        {
            return SecurityTokenDescriptor(encryptingCredentials, null, null);
        }

        public static SecurityTokenDescriptor SecurityTokenDescriptor(EncryptingCredentials encryptingCredentials, SigningCredentials signingCredentials, List<Claim> claims)
        {
            return new SecurityTokenDescriptor
            {
                Audience = Audience,
                EncryptingCredentials = encryptingCredentials,
                Expires = DateTime.UtcNow + TimeSpan.FromDays(1),
                Issuer = Issuer,
                IssuedAt = DateTime.UtcNow,
                NotBefore = DateTime.UtcNow,
                SigningCredentials = signingCredentials,
                Subject = claims == null ? ClaimsIdentity : new ClaimsIdentity(claims)
            };
        }

        public static SecurityTokenDescriptor SecurityTokenDescriptor(SigningCredentials signingCredentials)
        {
            return SecurityTokenDescriptor(null, signingCredentials, null);
        }

        public static string Session
        {
            get => "session";
        }

        public static TokenValidationParameters TokenValidationParameters(SecurityKey encryptionKey, SecurityKey signingKey)
        {
            return new TokenValidationParameters
            {
                AuthenticationType = AuthenticationType,
                TokenDecryptionKey = encryptionKey,
                IssuerSigningKey = signingKey,
                ValidAudience = Audience,
                ValidIssuer = Issuer,
            };
        }

        public static string UnsignedJwt
        {
            get => (new JwtSecurityTokenHandler()).CreateEncodedJwt(Issuer, Audience, ClaimsIdentity, null, null, null, null);
        }
    }
}