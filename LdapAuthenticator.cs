using System;
using System.Linq;
using System.Text.RegularExpressions;
using Novell.Directory.Ldap;

namespace Kevlatus.Ldap
{
    public class LdapAuthenticator
    {
        private const string MemberOfAttribute = "memberOf";
        private const string DisplayNameAttribute = "displayName";
        private const string SamAccountNameAttribute = "sAMAccountName";
        private const string MailAttribute = "mail";

        private readonly LdapConfig _config;
        private readonly LdapConnection _connection;

        public LdapAuthenticator(LdapConfig config)
        {
            _config = config;
            _connection = new LdapConnection();
        }

        public ActiveDirectoryIdentity Authenticate(string username, string password)
        {
            _connection.Connect(_config.Url, LdapConnection.DefaultPort);
            _connection.Bind(_config.Username, _config.Password);

            var searchFilter = string.Format(_config.SearchFilter, username);
            var result = _connection.Search(
                _config.SearchBase,
                LdapConnection.ScopeSub,
                searchFilter,
                new[]
                {
                    MemberOfAttribute,
                    DisplayNameAttribute,
                    SamAccountNameAttribute,
                    MailAttribute
                },
                false
            );

            try
            {
                var user = result.Next();
                if (user != null)
                {
                    _connection.Bind(user.Dn, password);
                    if (_connection.Bound)
                    {
                        var accountNameAttr = user.GetAttribute(SamAccountNameAttribute);
                        if (accountNameAttr == null)
                        {
                            throw new Exception("Your account is missing the account name.");
                        }

                        var displayNameAttr = user.GetAttribute(DisplayNameAttribute);
                        if (displayNameAttr == null)
                        {
                            throw new Exception("Your account is missing the display name.");
                        }

                        var memberAttr = user.GetAttribute(MemberOfAttribute);
                        if (memberAttr == null)
                        {
                            throw new Exception("Your account is missing roles.");
                        }

                        return new ActiveDirectoryIdentity(
                            accountNameAttr.StringValue,
                            displayNameAttr.StringValue,
                            memberAttr.StringValueArray
                                .Select(GetGroup)
                                .Where(x => x != null)
                                .Distinct()
                        );
                    }
                }
            }
            finally
            {
                _connection.Disconnect();
            }

            return null;
        }

        private static string GetGroup(string value)
        {
            var match = Regex.Match(value, "^CN=([^,]*)");
            return !match.Success ? null : match.Groups[1].Value;
        }
    }
}