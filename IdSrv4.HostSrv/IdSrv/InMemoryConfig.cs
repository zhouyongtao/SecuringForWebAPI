using IdentityServer4.Models;
using IdentityServer4.Test;
using System;
using System.Collections.Generic;
using System.Linq;

namespace IdSrv4.HostSrv.IdSrv
{
    public class InMemoryConfig
    {
        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            return new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResources.Email(),
                new IdentityResources.Phone(),
                new IdentityResources.Address()
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
                new ApiResource("api", "api service"),
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
                new Client
                {
                    ClientId = "client_1",
                    ClientSecrets = new [] { new Secret("123456".Sha256()) },
                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    AccessTokenType=AccessTokenType.Jwt,
                    AllowedScopes = GetApiResources().Select(t=>t.Name).ToArray()
                },
                new Client
                {
                    ClientId = "client_2",
                    ClientSecrets = new [] { new Secret("123456".Sha256()) },
                    AllowedGrantTypes = GrantTypes.ResourceOwnerPasswordAndClientCredentials,
                    AccessTokenType=AccessTokenType.Reference,

                    AllowedScopes = new [] { "user", "order" },
                    // Gets or sets a value indicating whether [allow offline access scope]. Defaults to false.
                    AllowOfflineAccess=true
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
                    Password = "123456"
                },
                new TestUser
                {
                    SubjectId = "2",
                    Username = "ytzhou",
                    Password = "123456"
                }
            };
        }
    }
}
