using IdentityModel;
using IdentityServer4.Models;
using IdentityServer4.Validation;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdSrv4.HostSrv.IdSrv
{
    public class ResourceOwnerPasswordValidator : IResourceOwnerPasswordValidator
    {
        public ResourceOwnerPasswordValidator()
        {

        }
        public async Task ValidateAsync(ResourceOwnerPasswordValidationContext context)
        {
            if (context.UserName == "irving" && context.Password == "123456")
            {
                context.Result = new GrantValidationResult(
                 subject: context.UserName,
                 authenticationMethod: "custom",
                 claims: GetUserClaims());
            }
            else
            {
                //验证失败
                context.Result = new GrantValidationResult(TokenRequestErrors.InvalidGrant, "invalid custom credential");
            }
        }
        //可以根据需要设置相应的Claim
        private Claim[] GetUserClaims()
        {
            return new Claim[]
            {
                new Claim(JwtClaimTypes.Subject,"1"),
                new Claim(JwtClaimTypes.Name,"irving"),
                new Claim(JwtClaimTypes.Role,"admin")
            };
        }
    }
}
