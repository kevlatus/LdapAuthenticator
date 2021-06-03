using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace Kevlatus.Ldap
{
    public class ActiveDirectoryIdentity : ClaimsIdentity
    {
        private static IEnumerable<Claim> BuildClaims(string username, string displayName, IEnumerable<string> roles)
        {
            var claims = new List<Claim>
            {
                new(ClaimTypes.NameIdentifier, username),
                new(ClaimTypes.Name, displayName),
            };
            claims.AddRange(
                roles.Select(it => new Claim(ClaimTypes.Role, it))
            );
            return claims;
        }

        internal ActiveDirectoryIdentity(string username, string displayName, IEnumerable<string> roles)
            : base(BuildClaims(username, displayName, roles), "LDAP")
        {
        }
    }
}