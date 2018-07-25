using IdentityServer4;
using IdentityServer4.Models;
using IdentityServer4.Test;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace IdSrv4.HostSrv.IdSrv
{
    /// <summary>
    /// 配置信息
    /// </summary>
    public class InMemoryConfig
    {
        // scopes define the resources in your system
        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            return new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                //new IdentityResources.Email(),
                //new IdentityResources.Phone(),
                //new IdentityResources.Address()
            };
        }

        /// <summary>
        /// Define which APIs will use this IdentityServer
        /// </summary>
        /// <returns></returns>
        public static IEnumerable<ApiResource> GetApiResources()
        {
            return new[]
            {
                new ApiResource("api", "api service")
                {
                  //  ApiSecrets = { new Secret("api_pwd".Sha256()) }
                },
                new ApiResource("user", "user service"),
                new ApiResource("order", "order service")
            };
        }

        /// <summary>
        /// Define which Apps will use thie IdentityServer
        /// </summary>
        /// <returns></returns>
        public static IEnumerable<Client> GetClients()
        {
            return new[]
            {
                // client credentials client
                new Client
                {
                    ClientId = "client_credentials_jwt_grant",
                    ClientSecrets = new [] { new Secret("123456".Sha256()) },
                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    AccessTokenType=AccessTokenType.Jwt,
                    AllowedScopes = GetApiResources().Select(t=>t.Name).ToArray()
                },
                // client credentials client
                new Client
                {
                    ClientId = "client_credentials_reference_grant",
                    ClientSecrets = new [] { new Secret("123456".Sha256()) },
                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    AccessTokenType=AccessTokenType.Reference,
                    AllowedScopes = GetApiResources().Select(t=>t.Name).ToArray()
                },
                // resource owner password grant client
                new Client
                {
                    ClientId = "client_password_grant",
                    ClientSecrets = new [] { new Secret("123456".Sha256()) },
                    AllowedGrantTypes = GrantTypes.ResourceOwnerPasswordAndClientCredentials,
                    AccessTokenType=AccessTokenType.Reference,
                    AllowedScopes = new [] { "user", "order"},
                },
                  // OpenID Connect hybrid flow and client credentials client (MVC)
                new Client
                {
                    ClientId = "mvc",
                    ClientName = "MVC Client",
                    AllowedGrantTypes = GrantTypes.HybridAndClientCredentials,
                    ClientSecrets =
                    {
                        new Secret("secret".Sha256())
                    },
                    RedirectUris = { "http://localhost:5002/signin-oidc" },
                    PostLogoutRedirectUris = { "http://localhost:5002/signout-callback-oidc" },
                    AllowedScopes =
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "api"
                    },
                    // Gets or sets a value indicating whether [allow offline access scope]. Defaults to false.
                    AllowOfflineAccess = true
                },

                // Implicit grant client
                new Client
                {
                    ClientId = "js",
                    ClientName = "JavaScript Client",
                    AllowedGrantTypes = GrantTypes.Implicit,
                    AllowAccessTokensViaBrowser = true,
                    RedirectUris = { "http://localhost:5003/callback.html" },
                    PostLogoutRedirectUris = { "http://localhost:5003/index.html" },
                    AllowedCorsOrigins = { "http://localhost:5003" },
                    AllowedScopes =
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "api"
                    },
                }
            };
        }

        /// <summary>
        /// Define which uses will use this IdentityServer
        /// </summary>
        /// <returns></returns>
        public static IEnumerable<TestUser> GetUsers()
        {
            return new[]
            {
                new TestUser
                {
                    SubjectId = "1",
                    Username = "irving",
                    Password = "123456",
                    Claims = new List<Claim>
                    {
                        new Claim("name", "irving"),
                        new Claim("website", "https://irving.com")
                    }
                },
                new TestUser
                {
                    SubjectId = "2",
                    Username = "ytzhou",
                    Password = "123456",
                    Claims = new List<Claim>
                    {
                        new Claim("name", "ytzhou"),
                        new Claim("website", "https://ytzhou.com")
                    }
                }
            };
        }
    }
}