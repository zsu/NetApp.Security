using Microsoft.Extensions.Options;
using Novell.Directory.Ldap;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Principal;
using System.Text;
using NetApp.Security.Extensions;
//using System.DirectoryServices.AccountManagement;
using NetApp.Common;
using System.Text.RegularExpressions;
//using System.DirectoryServices;

namespace NetApp.Security
{
    public class LdapService : ILdapService
    {
        //public const string CacheKeyADGroups = "ADGroups";
        protected readonly string _searchBase;

        protected readonly LdapSettings _ldapSettings;
        protected readonly IEncryptionService _encryptionService;

        protected readonly string[] _attributes =
        {
"objectSid", "objectGUID", "objectCategory", "objectClass", "memberOf", "name", "cn", "distinguishedName",
"sAMAccountName", "userPrincipalName", "displayName", "givenName", "sn", "description",
"telephoneNumber", "mail", "streetAddress", "postalCode", "l", "st", "co", "c",
"department","division","manager","title","userAccountControl","employeeID","initials"
};
        public LdapService(IOptions<LdapSettings> options)
        {
            this._ldapSettings = options.Value;
            this._searchBase = this._ldapSettings.SearchBase;
        }
        public LdapService(IOptions<LdapSettings> ldapSettingsOptions, IEncryptionService encryptionService)
        {
            this._ldapSettings = ldapSettingsOptions.Value;
            this._searchBase = this._ldapSettings.SearchBase;
            _encryptionService = encryptionService;
        }

        protected ILdapConnection GetConnection()
        {
            var ldapConnection = new LdapConnection() { SecureSocketLayer = this._ldapSettings.UseSSL };

            //Connect function will create a socket connection to the server - Port 389 for insecure and 3269 for secure    
            ldapConnection.Connect(this._ldapSettings.ServerName, this._ldapSettings.ServerPort);
            //Bind function with null user dn and password value will perform anonymous bind to LDAP server 
            ldapConnection.Bind(this._ldapSettings.Credentials.DomainUserName, _encryptionService!=null?_encryptionService.Decrypt(this._ldapSettings.Credentials.Password): this._ldapSettings.Credentials.Password);

            return ldapConnection;
        }

        public ICollection<LdapEntry> GetGroups(string groupName, bool getChildGroups = false)
        {
            var groups = new Collection<LdapEntry>();
            var filter = $"(&(objectClass=group)(cn={Microsoft.Security.Application.Encoder.LdapFilterEncode(groupName)}))";

            using (var ldapConnection = this.GetConnection())
            {
                var search = ldapConnection.Search(
                this._searchBase,
                LdapConnection.SCOPE_SUB,
                filter,
                this._attributes,
                false,
                null,
                null);

                LdapMessage message;

                while ((message = search.getResponse()) != null)
                {
                    if (!(message is LdapSearchResult searchResultMessage))
                    {
                        continue;
                    }

                    var entry = searchResultMessage.Entry;

                    groups.Add(this.CreateEntryFromAttributes(entry.DN, entry.getAttributeSet()));

                    if (!getChildGroups)
                    {
                        continue;
                    }

                    foreach (var child in this.GetChildren<LdapEntry>(string.Empty, entry.DN))
                    {
                        groups.Add(child);
                    }
                }
            }

            return groups.DistinctBy(x => x.Name).ToList();
        }

        public ICollection<LdapUser> GetAllUsers()
        {
            return this.GetUsersInGroups(null, null);
        }

        public ICollection<LdapUser> GetUsersInGroup(string group, string container = null)
        {
            return this.GetUsersInGroups(this.GetGroups(group), container);
        }

        public ICollection<LdapUser> GetUsersInGroups(ICollection<LdapEntry> groups, string container = null)
        {
            var users = new Collection<LdapUser>();

            if (groups == null || !groups.Any())
            {
                users.AddRange(this.GetChildren<LdapUser>(container ?? this._searchBase));
            }
            else
            {
                foreach (var group in groups)
                {
                    users.AddRange(this.GetChildren<LdapUser>(container ?? this._searchBase, @group.DistinguishedName));
                }
            }

            return users.DistinctBy(x => x.Name).ToList();
        }

        public ICollection<LdapUser> GetUsersByEmailAddress(string emailAddress)
        {
            var users = new Collection<LdapUser>();
            var filter = $"(&(objectClass=user)(mail={emailAddress}))";

            using (var ldapConnection = this.GetConnection())
            {
                var search = ldapConnection.Search(
                this._searchBase,
                LdapConnection.SCOPE_SUB,
                filter,
                this._attributes,
                false, null, null);

                LdapMessage message;

                while ((message = search.getResponse()) != null)
                {
                    if (!(message is LdapSearchResult searchResultMessage))
                    {
                        continue;
                    }

                    users.Add(this.CreateUserFromAttributes(this._searchBase,
                    searchResultMessage.Entry.getAttributeSet()));
                }
            }

            return users;
        }

        public LdapUser GetUserByName(string name)
        {
            LdapUser user = null;

            var filter = $"(&(objectClass=user)(name={name}))";
            filter = Microsoft.Security.Application.Encoder.LdapFilterEncode(filter);

            using (var ldapConnection = this.GetConnection())
            {
                var search = ldapConnection.Search(
                this._searchBase,
                LdapConnection.SCOPE_SUB,
                filter,
                this._attributes,
                false,
                null,
                null);

                LdapMessage message;

                while ((message = search.getResponse()) != null)
                {
                    if (!(message is LdapSearchResult searchResultMessage))
                    {
                        continue;
                    }

                    user = this.CreateUserFromAttributes(this._searchBase, searchResultMessage.Entry.getAttributeSet());
                }
            }

            return user;
        }
        public LdapUser GetUserByLogonName(string username)
        {
            LdapUser user = null;

            var filter = $"(&(objectClass=user)(sAMAccountName={username?.Trim()}))";

            using (var ldapConnection = this.GetConnection())
            {
                var search = ldapConnection.Search(
                this._searchBase,
                LdapConnection.SCOPE_SUB,
                filter,
                this._attributes,
                false,
                null,
                null);

                LdapMessage message;

                while ((message = search.getResponse()) != null)
                {
                    if (!(message is LdapSearchResult searchResultMessage))
                    {
                        continue;
                    }

                    user = this.CreateUserFromAttributes(this._searchBase, searchResultMessage.Entry.getAttributeSet());
                }
            }

            return user;
        }
        public List<LdapUser> GetUser(string firstname, string lastname)
        {
            List<LdapUser> user = new List<LdapUser>();

            var filter = $"(&(objectClass=user)(givenName={firstname})(sn={lastname}))";

            using (var ldapConnection = this.GetConnection())
            {
                var search = ldapConnection.Search(
                this._searchBase,
                LdapConnection.SCOPE_SUB,
                filter,
                this._attributes,
                false,
                null,
                null);

                LdapMessage message;

                while ((message = search.getResponse()) != null)
                {
                    if (!(message is LdapSearchResult searchResultMessage))
                    {
                        continue;
                    }

                    user.Add(this.CreateUserFromAttributes(this._searchBase, searchResultMessage.Entry.getAttributeSet()));
                }
            }

            return user;
        }
        //public LdapUser GetAdministrator()
        //{
        //    var name = this._ldapSettings.Credentials.DomainUserName.Substring(
        //     this._ldapSettings.Credentials.DomainUserName.IndexOf("\\", StringComparison.Ordinal) != -1
        //      ? this._ldapSettings.Credentials.DomainUserName.IndexOf("\\", StringComparison.Ordinal) + 1
        //      : 0);

        //    return this.GetUserByCommonName(name);
        //}
        //public void AddUser(LdapUser user, string container)
        //{

        //    PrincipalContext ctx = new PrincipalContext(ContextType.Domain, _ldapSettings.ServerName + ":" + _ldapSettings.ServerPort, container ?? _ldapSettings.DomainDistinguishedName, _ldapSettings.UseSSL ? ContextOptions.SimpleBind | ContextOptions.SecureSocketLayer : ContextOptions.Negotiate | ContextOptions.Signing | ContextOptions.Sealing, _ldapSettings.Credentials.DomainUserName, _encryptionService.Decrypt(_ldapSettings.Credentials.Password));
        //    var item = new UserPrincipal(ctx, user.UserName.Trim(), user.Password, false);
        //    item.UserPrincipalName = user.UserName.Trim();
        //    item.GivenName = user.FirstName?.Trim();
        //    item.Surname = user.LastName?.Trim();
        //    string fullName = user.FullName;
        //    //newuser.DisplayName = fullName;
        //    //newuser.Name = fullName;
        //    if (user.EmailAddress != null)
        //    {
        //        item.EmailAddress = user.EmailAddress;
        //    }
        //    if (user.Name != null)
        //    {
        //        item.Name = user.Name;
        //    }
        //    else
        //    {
        //        item.Name = fullName;
        //    }
        //    if (user.DisplayName != null)
        //    {
        //        item.DisplayName = user.DisplayName?.Trim();
        //    }
        //    else
        //    {
        //        item.DisplayName = fullName;
        //    }
        //    if (user.Description != null)
        //    {
        //        item.Description = user.Description;
        //    }
        //    if (user.Phone != null)
        //    {
        //        item.VoiceTelephoneNumber = user.Phone;
        //    }
        //    item.Save();

        //    if (user.Address?.Street != null)
        //    {
        //        ((DirectoryEntry)item.GetUnderlyingObject()).Properties["streetAddress"].Value = user.Address.Street;
        //    }
        //    if (user.Address?.City != null)
        //    {
        //        ((DirectoryEntry)item.GetUnderlyingObject()).Properties["l"].Value = user.Address.City;
        //    }
        //    if (user.Address?.PostalCode != null)
        //    {
        //        ((DirectoryEntry)item.GetUnderlyingObject()).Properties["postalCode"].Value = user.Address.PostalCode;
        //    }
        //    if (user.Address?.StateName != null)
        //    {
        //        ((DirectoryEntry)item.GetUnderlyingObject()).Properties["st"].Value = user.Address.StateName;
        //    }
        //    if (user.Address?.CountryName != null)
        //    {
        //        ((DirectoryEntry)item.GetUnderlyingObject()).Properties["co"].Value = user.Address.CountryName;
        //    }
        //    if (user.Address?.CountryCode != null)
        //    {
        //        ((DirectoryEntry)item.GetUnderlyingObject()).Properties["c"].Value = user.Address.CountryCode;
        //    }
        //    if (user.MiddleName != null)
        //    {
        //        ((DirectoryEntry)item.GetUnderlyingObject()).Properties["initials"].Value = user.MiddleName.Trim();
        //    }
        //    if (user.EmployeeId != null)
        //    {
        //        ((DirectoryEntry)item.GetUnderlyingObject()).Properties["employeeID"].Value = user.EmployeeId;
        //    }
        //    if (user.Division != null)
        //    {
        //        ((DirectoryEntry)item.GetUnderlyingObject()).Properties["division"].Value = user.Division;
        //    }
        //    if (user.Department != null)
        //    {
        //        ((DirectoryEntry)item.GetUnderlyingObject()).Properties["department"].Value = user.Department;
        //    }
        //    if (user.Manager != null)
        //    {
        //        var manager = GetUserByLogonName(user.Manager);
        //        if (manager != null)
        //            ((DirectoryEntry)item.GetUnderlyingObject()).Properties["manager"].Value = manager.DistinguishedName;
        //    }
        //    if (user.Title != null)
        //    {
        //        ((DirectoryEntry)item.GetUnderlyingObject()).Properties["title"].Value = user.Title;
        //    }
        //    item.Save();
        //}
        public void SetPasswordNeverExpires(string username, bool neverExpire)
        {
            if (string.IsNullOrWhiteSpace(username))
                throw new ArgumentNullException(nameof(username));
            //var user = GetUser(username);
            //if (user == null)
            //    throw new Exception($"Invalid user {username}.");
            //user.PasswordNeverExpires = neverExpire;
            //user.Save();
            var user = GetUserByLogonName(username);
            if (user == null)
                throw new Exception($"Invalid user {username}.");
            var flag = Convert.ToInt32(user.AccountFlag);
            flag = neverExpire ? flag | 0x10000 : flag & ~0x10000;
            SetUserAttributes(username, new List<KeyValuePair<string, string>> { new KeyValuePair<string, string>("userAccountControl", flag.ToString()) });
        }
        public void SetPasswordExpired(string username, bool expired = true)
        {
            if (string.IsNullOrWhiteSpace(username))
                throw new ArgumentNullException(nameof(username));
            //var user = GetUser(username);
            //if (user == null)
            //    throw new Exception($"Invalid user {username}.");
            //user.PasswordNeverExpires = neverExpire;
            //user.Save();
            var user = GetUserByLogonName(username);
            if (user == null)
                throw new Exception($"Invalid user {username}.");
            var flag = Convert.ToInt32(user.AccountFlag);
            flag = expired ? flag | 0x800000 : flag & ~0x800000;
            SetUserAttributes(username, new List<KeyValuePair<string, string>> { new KeyValuePair<string, string>("userAccountControl", flag.ToString()) });
            SetUserAttributes(username, new List<KeyValuePair<string, string>> { new KeyValuePair<string, string>("pwdLastSet", expired ? "0" : "-1") });
        }
        public void SetManager(string username, string managerName)
        {
            if (string.IsNullOrWhiteSpace(username))
                throw new ArgumentNullException(nameof(username));
            string managerDn = null;
            if (!string.IsNullOrWhiteSpace(managerName))
            {
                var manager = GetUserByLogonName(managerName);
                if (manager == null)
                    throw new Exception($"Invalid user {managerName}.");
                managerDn = manager.DistinguishedName;
            }
            SetUserAttributes(username, new List<KeyValuePair<string, string>> { new KeyValuePair<string, string>("manager", managerDn) });
        }
        public void AddUser(LdapUser user, string container)
        {
            var dn = $"CN={user.FullName},{container ?? _ldapSettings.DomainDistinguishedName}";

            var attributeSet = new LdapAttributeSet
 {
 new LdapAttribute("instanceType", "4"),
 new LdapAttribute("objectCategory", $"CN=Person,CN=Schema,CN=Configuration,{this._ldapSettings.DomainDistinguishedName}"),
 new LdapAttribute("objectClass", new[] {"top", "person", "organizationalPerson", "user"}),
 new LdapAttribute("name", user.FullName),
 new LdapAttribute("cn", $"{user.FullName}"),
 new LdapAttribute("sAMAccountName", user.UserName?.Trim().ToLower()),
 new LdapAttribute("userPrincipalName", $"{user.UserName.Trim().ToLower()}@{this._ldapSettings.DomainName?.Trim()}"),
 new LdapAttribute("unicodePwd", SupportClass.ToSByteArray(Encoding.Unicode.GetBytes($"\"{user.Password?.Trim()}\""))),
 new LdapAttribute("userAccountControl", user.MustChangePasswordOnNextLogon ? "544" : "512"),
 new LdapAttribute("givenName", user.FirstName?.Trim()),
 new LdapAttribute("sn", user.LastName?.Trim()),
         //new LdapAttribute("mail", user.EmailAddress)
        };
            if (!string.IsNullOrWhiteSpace(user.EmailAddress))
            {
                attributeSet.Add(new LdapAttribute("mail", user.EmailAddress.Trim()));
            }
            if (!string.IsNullOrWhiteSpace(user.DisplayName))
            {
                attributeSet.Add(new LdapAttribute("displayName", user.DisplayName.Trim()));
            }
            else
                attributeSet.Add(new LdapAttribute("displayName", user.FullName));
            if (!string.IsNullOrWhiteSpace(user.MiddleName))
            {
                attributeSet.Add(new LdapAttribute("initials", user.MiddleName.Trim()));
            }
            if (!string.IsNullOrWhiteSpace(user.Description))
            {
                attributeSet.Add(new LdapAttribute("description", user.Description.Trim()));
            }
            if (!string.IsNullOrWhiteSpace(user.Phone))
            {
                attributeSet.Add(new LdapAttribute("telephoneNumber", user.Phone.Trim()));
            }
            if (!string.IsNullOrWhiteSpace(user.Address?.Street))
            {
                attributeSet.Add(new LdapAttribute("streetAddress", user.Address.Street.Trim()));
            }
            if (!string.IsNullOrWhiteSpace(user.Address?.City))
            {
                attributeSet.Add(new LdapAttribute("l", user.Address.City.Trim()));
            }
            if (!string.IsNullOrWhiteSpace(user.Address?.PostalCode))
            {
                attributeSet.Add(new LdapAttribute("postalCode", user.Address.PostalCode.Trim()));
            }
            if (!string.IsNullOrWhiteSpace(user.Address?.StateName))
            {
                attributeSet.Add(new LdapAttribute("st", user.Address.StateName.Trim()));
            }
            if (user.Address?.CountryName != null)
            {
                attributeSet.Add(new LdapAttribute("co", user.Address.CountryName));
            }
            if (!string.IsNullOrWhiteSpace(user.Address?.CountryCode))
            {
                attributeSet.Add(new LdapAttribute("c", user.Address.CountryCode.Trim()));
            }
            if (!string.IsNullOrWhiteSpace(user.EmployeeId))
            {
                attributeSet.Add(new LdapAttribute("employeeID", user.EmployeeId.Trim()));
            }
            if (!string.IsNullOrWhiteSpace(user.Division))
            {
                attributeSet.Add(new LdapAttribute("division", user.Division.Trim()));
            }
            if (!string.IsNullOrWhiteSpace(user.Department))
            {
                attributeSet.Add(new LdapAttribute("department", user.Department.Trim()));
            }
            if (!string.IsNullOrWhiteSpace(user.Manager))
            {
                var manager = GetUserByLogonName(user.Manager.Trim());
                if (manager == null)
                    throw new Exception($"Invalid manager {user.Manager}.");
                attributeSet.Add(new LdapAttribute("manager", manager.DistinguishedName));
            }
            if (!string.IsNullOrWhiteSpace(user.Title))
            {
                attributeSet.Add(new LdapAttribute("title", user.Title.Trim()));
            }
            var newEntry = new Novell.Directory.Ldap.LdapEntry(dn, attributeSet);

            using (var ldapConnection = this.GetConnection())
            {
                ldapConnection.Add(newEntry);
            }
        }

        public bool Authenticate(string distinguishedName, string password)
        {
            using (var ldapConnection = new LdapConnection() { SecureSocketLayer = _ldapSettings.UseSSL })
            {
                ldapConnection.Connect(this._ldapSettings.ServerName, this._ldapSettings.ServerPort);
                try
                {
                    ldapConnection.Bind(distinguishedName + (string.IsNullOrWhiteSpace(_ldapSettings.DomainName) ? string.Empty : "@" + _ldapSettings.DomainName), password);
                    return true;
                }
                catch (Exception)
                {
                    return false;
                }
            }
        }
        public void ChangePassword(string username, string password, bool forceChange = true)
        {
            if (string.IsNullOrWhiteSpace(username))
                throw new ArgumentNullException("username");
            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentNullException("password");
            var user = GetUserByLogonName(username);
            if (user == null)
                throw new Exception($"Invalid user {username}.");
            var encodedBytes = SupportClass.ToSByteArray(Encoding.Unicode.GetBytes($"\"{password}\""));
            var attributePassword = new LdapAttribute("unicodePwd", encodedBytes);
            using (var ldapConnection = this.GetConnection())
            {
                ldapConnection.Modify(user.DistinguishedName, new LdapModification(LdapModification.REPLACE, attributePassword));
            }
            if (forceChange)
            {
                var flag = Convert.ToInt32(user.AccountFlag);
                flag = flag | 0x800000;
                SetUserAttributes(username, new List<KeyValuePair<string, string>> { new KeyValuePair<string, string>("userAccountControl", flag.ToString()) });
            }
            //PrincipalContext ctx = new PrincipalContext(ContextType.Domain, _ldapSettings.ServerName + ":" + _ldapSettings.ServerPort, _ldapSettings.DomainDistinguishedName, _ldapSettings.UseSSL ? ContextOptions.SimpleBind | ContextOptions.SecureSocketLayer : ContextOptions.Negotiate | ContextOptions.Signing | ContextOptions.Sealing, _ldapSettings.Credentials.DomainUserName, _encryptionService.Decrypt(_ldapSettings.Credentials.Password));
            //UserPrincipal user = UserPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, username);
            ////Reset User Password
            //user.SetPassword(password);
            ////Force user to change password at next logon
            //if (forceChange)
            //    user.ExpirePasswordNow();
            //user.Save();
        }
        public List<LdapUser> GetSubordinates(string managerUsername)
        {
            List<LdapUser> user = new List<LdapUser>();
            var manager = GetUserByLogonName(managerUsername);
            if (manager == null)
                throw new Exception($"{managerUsername} cannot be found.");

            var filter = $"(&(objectClass=user)(manager={Microsoft.Security.Application.Encoder.LdapFilterEncode(manager.DistinguishedName)}))";

            using (var ldapConnection = this.GetConnection())
            {
                var search = ldapConnection.Search(
                this._searchBase,
                LdapConnection.SCOPE_SUB,
                filter,
                this._attributes,
                false,
                null,
                null);

                LdapMessage message;

                while ((message = search.getResponse()) != null)
                {
                    if (!(message is LdapSearchResult searchResultMessage))
                    {
                        continue;
                    }

                    user.Add(this.CreateUserFromAttributes(this._searchBase, searchResultMessage.Entry.getAttributeSet()));
                }
            }

            return user;
        }

        protected virtual ICollection<T> GetChildren<T>(string searchBase, string groupDistinguishedName = null, bool recursive = true)
        where T : ILdapEntry, new()
        {
            var entries = new Collection<T>();

            var objectCategory = "*";
            var objectClass = "*";

            if (typeof(T) == typeof(LdapEntry))
            {
                objectClass = "group";
                objectCategory = "group";

                entries = this.GetChildren(searchBase ?? this._searchBase, groupDistinguishedName, objectCategory, objectClass, recursive)
                .Cast<T>().ToCollection();

            }

            if (typeof(T) == typeof(LdapUser))
            {
                objectCategory = "person";
                objectClass = "user";

                entries = this.GetChildren(searchBase ?? this._searchBase, groupDistinguishedName, objectCategory, objectClass, recursive).Cast<T>()
                .ToCollection();

            }

            return entries;
        }

        protected virtual ICollection<ILdapEntry> GetChildren(string searchBase, string groupDistinguishedName = null,
        string objectCategory = "*", string objectClass = "*", bool recursive = true)
        {
            var allChildren = new Collection<ILdapEntry>();
            var filter = string.IsNullOrEmpty(groupDistinguishedName)
            ? $"(&(objectCategory={objectCategory})(objectClass={objectClass}))"
            : ($"(&(objectCategory={objectCategory})(objectClass={objectClass})(memberOf={Microsoft.Security.Application.Encoder.LdapFilterEncode(groupDistinguishedName)}))");

            using (var ldapConnection = this.GetConnection())
            {
                var search = ldapConnection.Search(
                searchBase ??= this._searchBase,
                LdapConnection.SCOPE_SUB,
                filter,
                this._attributes,
                false,
                null,
                null);

                LdapMessage message;

                while ((message = search.getResponse()) != null)
                {
                    if (!(message is LdapSearchResult searchResultMessage))
                    {
                        continue;
                    }

                    var entry = searchResultMessage.Entry;

                    if (objectClass == "group")
                    {
                        allChildren.Add(this.CreateEntryFromAttributes(entry.DN, entry.getAttributeSet()));
                        if (recursive)
                        {
                            foreach (var child in this.GetChildren(searchBase, entry.DN, objectCategory, objectClass, recursive))
                            {
                                allChildren.Add(child);
                            }
                        }
                    }

                    if (objectClass == "user")
                    {
                        allChildren.Add(this.CreateUserFromAttributes(entry.DN, entry.getAttributeSet()));
                    }
                }
            }

            return allChildren;
        }
        protected virtual ICollection<T> GetParent<T>(string searchBase, string groupDistinguishedName = null, bool recursive = true) where T : ILdapEntry, new()
        {
            var entries = new Collection<T>();

            var objectCategory = "*";
            var objectClass = "*";

            if (typeof(T) == typeof(LdapEntry))
            {
                objectClass = "group";
                objectCategory = "group";

                entries = this.GetParent(searchBase ?? this._searchBase, groupDistinguishedName, objectCategory, objectClass, recursive)
                .Cast<T>().ToCollection();

            }

            if (typeof(T) == typeof(LdapUser))
            {
                objectCategory = "person";
                objectClass = "user";

                entries = this.GetParent(searchBase ?? this._searchBase, groupDistinguishedName, objectCategory, objectClass, recursive).Cast<T>()
                .ToCollection();

            }

            return entries;
        }

        protected virtual ICollection<ILdapEntry> GetParent(string searchBase, string groupDistinguishedName = null,
        string objectCategory = "*", string objectClass = "*", bool recursive = true)
        {
            var allChildren = new Collection<ILdapEntry>();

            var filter = string.IsNullOrEmpty(groupDistinguishedName)
            ? $"(&(objectCategory={objectCategory})(objectClass={objectClass}))"
            : ($"(&(objectCategory={objectCategory})(objectClass={objectClass})(member={Microsoft.Security.Application.Encoder.LdapFilterEncode(groupDistinguishedName)}))");
            using (var ldapConnection = this.GetConnection())
            {
                var search = ldapConnection.Search(
                searchBase ??= this._searchBase,
                LdapConnection.SCOPE_SUB,
                filter,
                this._attributes,
                false,
                null,
                null);

                LdapMessage message;

                while ((message = search.getResponse()) != null)
                {
                    if (!(message is LdapSearchResult searchResultMessage))
                    {
                        continue;
                    }

                    var entry = searchResultMessage.Entry;

                    if (objectClass == "group")
                    {
                        allChildren.Add(this.CreateEntryFromAttributes(entry.DN, entry.getAttributeSet()));
                        if (recursive)
                        {
                            foreach (var child in this.GetParent(searchBase, entry.DN, objectCategory, objectClass, recursive))
                            {
                                allChildren.Add(child);
                            }
                        }
                    }

                    if (objectClass == "user")
                    {
                        allChildren.Add(this.CreateUserFromAttributes(entry.DN, entry.getAttributeSet()));
                    }
                }
            }

            return allChildren;
        }
        protected LdapUser CreateUserFromAttributes(string distinguishedName, LdapAttributeSet attributeSet)
        {
            var ldapUser = new LdapUser
            {
                ObjectSid = attributeSet.getAttribute("objectSid")?.StringValue,
                ObjectGuid = ConvertToString(attributeSet.getAttribute("objectGUID")?.ByteValue),
                ObjectCategory = attributeSet.getAttribute("objectCategory")?.StringValue,
                ObjectClass = attributeSet.getAttribute("objectClass")?.StringValue,
                IsDomainAdmin = attributeSet.getAttribute("memberOf") != null && attributeSet.getAttribute("memberOf").StringValueArray.Contains("CN=Domain Admins," + this._ldapSettings.SearchBase),
                MemberOf = attributeSet.getAttribute("memberOf")?.StringValueArray,
                CommonName = attributeSet.getAttribute("cn")?.StringValue,
                UserName = attributeSet.getAttribute("name")?.StringValue,
                SamAccountName = attributeSet.getAttribute("sAMAccountName")?.StringValue,
                UserPrincipalName = attributeSet.getAttribute("userPrincipalName")?.StringValue,
                Name = attributeSet.getAttribute("name")?.StringValue,
                DistinguishedName = attributeSet.getAttribute("distinguishedName")?.StringValue ?? distinguishedName,
                DisplayName = attributeSet.getAttribute("displayName")?.StringValue,
                FirstName = attributeSet.getAttribute("givenName")?.StringValue,
                LastName = attributeSet.getAttribute("sn")?.StringValue,
                Description = attributeSet.getAttribute("description")?.StringValue,
                Phone = attributeSet.getAttribute("telephoneNumber")?.StringValue,
                EmailAddress = attributeSet.getAttribute("mail")?.StringValue,
                Address = new LdapAddress
                {
                    Street = attributeSet.getAttribute("streetAddress")?.StringValue,
                    City = attributeSet.getAttribute("l")?.StringValue,
                    PostalCode = attributeSet.getAttribute("postalCode")?.StringValue,
                    StateName = attributeSet.getAttribute("st")?.StringValue,
                    CountryName = attributeSet.getAttribute("co")?.StringValue,
                    CountryCode = attributeSet.getAttribute("c")?.StringValue
                },

                SamAccountType = int.Parse(attributeSet.getAttribute("sAMAccountType")?.StringValue ?? "0"),
                MiddleName = attributeSet.getAttribute("initials")?.StringValue,
                EmployeeId = attributeSet.getAttribute("employeeID")?.StringValue,
                Title = attributeSet.getAttribute("title")?.StringValue,
                Division = attributeSet.getAttribute("division")?.StringValue,
                Department = attributeSet.getAttribute("department")?.StringValue,
                Manager = attributeSet.getAttribute("manager")?.StringValue,
                AccountFlag = attributeSet.getAttribute("userAccountControl").StringValue
            };

            return ldapUser;
        }

        protected LdapEntry CreateEntryFromAttributes(string distinguishedName, LdapAttributeSet attributeSet)
        {
            return new LdapEntry
            {
                ObjectSid = attributeSet.getAttribute("objectSid")?.StringValue,
                ObjectGuid = attributeSet.getAttribute("objectGUID")?.StringValue,
                ObjectCategory = attributeSet.getAttribute("objectCategory")?.StringValue,
                ObjectClass = attributeSet.getAttribute("objectClass")?.StringValue,
                CommonName = attributeSet.getAttribute("cn")?.StringValue,
                Name = attributeSet.getAttribute("name")?.StringValue,
                DistinguishedName = attributeSet.getAttribute("distinguishedName")?.StringValue ?? distinguishedName,
                SamAccountName = attributeSet.getAttribute("sAMAccountName")?.StringValue,
                SamAccountType = int.Parse(attributeSet.getAttribute("sAMAccountType")?.StringValue ?? "0"),
            };
        }

        //private SecurityIdentifier GetDomainSid()
        //{
        //    var administratorAcount = new NTAccount(this._ldapSettings.DomainName, "administrator");
        //    var administratorSId = (SecurityIdentifier)administratorAcount.Translate(typeof(SecurityIdentifier));
        //    return administratorSId.AccountDomainSid;
        //}

        private IEnumerable<string> GetGroupsForUser(string username)
        {
            //var items = _cache?.Get<Dictionary<string, HashSet<string>>>(CacheKeyADGroups);
            //var item = items?[userName];
            //if (item != null)
            //    return item;
            //else
            //{
            var groups = new Stack<string>();
            var uniqueGroups = new HashSet<string>();

            foreach (string group in this.GetGroupsForUserCore(username))
                uniqueGroups.Add(group);

            //if (items == null)
            //{
            //    items = new Dictionary<string, HashSet<string>>();
            //    items.Add(userName, uniqueGroups);
            //    _cache?.Set(CacheKeyADGroups, items);
            //}
            //else
            //{
            //    items.Add(userName, uniqueGroups);
            //}
            return uniqueGroups;
        }
        /// <summary>
        /// Get nested groups membership for user
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        private IEnumerable<string> GetNestedGroupsForUser(string username)
        {
            //var items = _cache?.Get<Dictionary<string, HashSet<string>>>(CacheKeyADGroups);
            //var item = items?[username];
            //if (item != null)
            //    return item;
            //else
            //{
            Dictionary<string, HashSet<string>> items = null;
            var groups = new Stack<string>();
            var uniqueGroups = new HashSet<string>();

            foreach (string group in this.GetGroupsForUserCore(username))
                groups.Push(group);

            while (groups.Count > 0)
            {
                string group = groups.Pop();
                uniqueGroups.Add(group);

                foreach (string parentGroup in this.GetGroupsForUserCore(group))
                    groups.Push(parentGroup);
            }
            if (items == null)
            {
                items = new Dictionary<string, HashSet<string>>();
                items.Add(username, uniqueGroups);
                //_cache?.Set(CacheKeyADGroups, items);
            }
            else
            {
                items.Add(username, uniqueGroups);
            }
            return uniqueGroups;
            //}
        }

        private IEnumerable<string> GetGroupsForUserCore(string username)
        {
            using (var ldapConnection = this.GetConnection())
            {
                LdapSearchQueue searchQueue = ldapConnection.Search(
                _searchBase,
                LdapConnection.SCOPE_SUB,
                $"(sAMAccountName={username})",
                new string[] { "cn", "memberOf" },
                false,
                null as LdapSearchQueue);

                LdapMessage message;
                while ((message = searchQueue.getResponse()) != null)
                {
                    if (message is LdapSearchResult searchResult)
                    {
                        var entry = searchResult.Entry;
                        foreach (string value in HandleEntry(entry))
                            yield return value;
                    }
                    else
                        continue;
                }
            }

            IEnumerable<string> HandleEntry(Novell.Directory.Ldap.LdapEntry entry)
            {
                LdapAttribute attr = entry.getAttribute("memberOf");

                if (attr == null) yield break;

                foreach (string value in attr.StringValueArray)
                {
                    string groupName = GetCN(value);
                    yield return groupName;
                }
            }
        }
        private string GetCN(string value)
        {
            Match match = Regex.Match(value, "^CN=([^,]*)");

            if (!match.Success) return null;

            return match.Groups[1].Value;
        }
        //public bool IsUserInGroup(string distinguishedName, List<string> groups)
        //{
        //    if (string.IsNullOrWhiteSpace(distinguishedName) || groups == null || groups.Count() == 0)
        //        return false;
        //    PrincipalContext ctx = new PrincipalContext(ContextType.Domain, _ldapSettings.ServerName + ":" + _ldapSettings.ServerPort, _ldapSettings.DomainDistinguishedName, _ldapSettings.UseSSL ? ContextOptions.SimpleBind | ContextOptions.SecureSocketLayer : ContextOptions.Negotiate | ContextOptions.Signing | ContextOptions.Sealing, _ldapSettings.Credentials.DomainUserName, _encryptionService.Decrypt(_ldapSettings.Credentials.Password));

        //    // find a user
        //    UserPrincipal user = UserPrincipal.FindByIdentity(ctx, distinguishedName.TrimAssignToGroups
        //    foreach (var item in groups)
        //    {
        //        // find the group in question
        //        GroupPrincipal group = GroupPrincipal.FindByIdentity(ctx, item);

        //        if (user != null && group != null)
        //        {
        //            var allmembers = group.GetMembers(true);
        //            if (allmembers.Any(x => x.Guid == user.Guid))
        //            {
        //                return true;
        //            }
        //            //else
        //            //    return false;
        //        }
        //        //else
        //        //{
        //        //    return false;
        //        //}
        //    }
        //    return false;
        //}
        public bool IsUserInGroup(string username, List<string> groups, bool checkNested = true)
        {
            if (string.IsNullOrWhiteSpace(username) || groups == null || groups.Count() == 0)
                return false;
            var userGroups = GetUserGroups(username, checkNested);//checkNested?GetNestedGroupsForUser(username) : GetGroupsForUser(username);
            if (userGroups == null || userGroups.Count() <= 1)
                return false;
            //if (userGroups.Intersect(groups).Any())
            //    return true;
            foreach (var item in groups)
            {
                if (userGroups.Contains(item))
                    return true;
            }
            return false;
        }
        public void AddToGroups(string username, List<string> groups)
        {
            if (string.IsNullOrWhiteSpace(username) || groups == null || groups.Count() == 0)
                return;
            var userDn = GetUserByLogonName(username)?.DistinguishedName;
            if (string.IsNullOrWhiteSpace(userDn))
                throw new Exception($"Invalid user {username}.");
            var userGroups = GetUserGroups(username, false);
            var groupsToAdd = groups?.Except(userGroups);
            if (groupsToAdd == null || groupsToAdd?.Count() == 0) return;
            using (var ldapConnection = this.GetConnection())
            {
                foreach (var item in groupsToAdd)
                {
                    var groupDn = GetGroups(item)?.FirstOrDefault()?.DistinguishedName;
                    if (string.IsNullOrWhiteSpace(groupDn))
                        throw new Exception($"Invalid group {item}.");
                    LdapModification[] modGroup = new LdapModification[1];
                    LdapAttribute member = new LdapAttribute("member", userDn);
                    modGroup[0] = new LdapModification(LdapModification.ADD, member);
                    ldapConnection.Modify(groupDn, modGroup);
                }
            }
            //if (string.IsNullOrWhiteSpace(username) || groups == null || groups.Count() == 0)
            //    return;
            //PrincipalContext ctx = new PrincipalContext(ContextType.Domain, _ldapSettings.ServerName + ":" + _ldapSettings.ServerPort, _ldapSettings.DomainDistinguishedName, _ldapSettings.UseSSL ? ContextOptions.SimpleBind | ContextOptions.SecureSocketLayer : ContextOptions.Negotiate | ContextOptions.Signing | ContextOptions.Sealing, _ldapSettings.Credentials.DomainUserName, _encryptionService.Decrypt(_ldapSettings.Credentials.Password));
            //UserPrincipal user = UserPrincipal.FindByIdentity(ctx, username.Trim());
            //if (user == null)
            //    throw new Exception($"Invalid user {username}");
            //foreach (var item in groups)
            //{
            //    GroupPrincipal group = GroupPrincipal.FindByIdentity(ctx, item);
            //    if (group == null)
            //        throw new Exception($"Invalid group {item}");
            //    if (!group.Members.Any(x => x.DistinguishedName == user.DistinguishedName))
            //    {
            //        group.Members.Add(user);
            //        group.Save();
            //    }
            //}
        }
        public void RemoveFromGroups(string username, List<string> groups)
        {
            if (string.IsNullOrWhiteSpace(username) || groups == null || groups.Count() == 0)
                return;
            var userDn = GetUserByLogonName(username)?.DistinguishedName;
            if (string.IsNullOrWhiteSpace(userDn))
                throw new Exception($"Invalid user {username}.");
            var userGroups = GetUserGroups(username, false);
            var groupsToRemove = groups?.Intersect(userGroups);
            if (groupsToRemove == null || groupsToRemove?.Count() == 0) return;
            using (var ldapConnection = this.GetConnection())
            {
                foreach (var item in groups)
                {
                    var groupDn = GetGroups(item)?.FirstOrDefault()?.DistinguishedName;
                    if (string.IsNullOrWhiteSpace(groupDn))
                        throw new Exception($"Invalid group {item}.");
                    LdapModification[] modGroup = new LdapModification[1];
                    LdapAttribute member = new LdapAttribute("member", userDn);
                    modGroup[0] = new LdapModification(LdapModification.DELETE, member);
                    ldapConnection.Modify(groupDn, modGroup);
                }
            }
            //PrincipalContext ctx = new PrincipalContext(ContextType.Domain, _ldapSettings.ServerName + ":" + _ldapSettings.ServerPort, _ldapSettings.DomainDistinguishedName, _ldapSettings.UseSSL ? ContextOptions.SimpleBind | ContextOptions.SecureSocketLayer : ContextOptions.Negotiate | ContextOptions.Signing | ContextOptions.Sealing, _ldapSettings.Credentials.DomainUserName, _encryptionService.Decrypt(_ldapSettings.Credentials.Password));
            //UserPrincipal user = UserPrincipal.FindByIdentity(ctx, username.Trim());
            //if (user == null)
            //    throw new Exception($"Invalid user {username}");
            //foreach (var item in groups)
            //{
            //    GroupPrincipal group = GroupPrincipal.FindByIdentity(ctx, item);
            //    if (group == null)
            //        throw new Exception($"Invalid group {item}");
            //    if (group.Members.Any(x => x.DistinguishedName == user.DistinguishedName))
            //    {
            //        group.Members.Remove(user);
            //        group.Save();
            //    }
            //}
        }
        //public List<string> GetUserGroups(string distinguishedName)
        //{
        //    List<string> result = new List<string>();

        //    if (string.IsNullOrWhiteSpace(distinguishedName))
        //        return null;
        //    PrincipalContext ctx = new PrincipalContext(ContextType.Domain, _ldapSettings.ServerName + ":" + _ldapSettings.ServerPort, _ldapSettings.DomainDistinguishedName, _ldapSettings.UseSSL ? ContextOptions.SimpleBind | ContextOptions.SecureSocketLayer : ContextOptions.Negotiate | ContextOptions.Signing | ContextOptions.Sealing, _ldapSettings.Credentials.DomainUserName, _encryptionService.Decrypt(_ldapSettings.Credentials.Password));
        //    UserPrincipal user = UserPrincipal.FindByIdentity(ctx, distinguishedName.Trim());
        //    if (user != null)
        //    {
        //        PrincipalSearchResult<Principal> groups = user.GetGroups();//.GetAuthorizationGroups();
        //        result = groups.Select(x => x.SamAccountName).ToList();
        //        //foreach (Principal p in groups)
        //        //{
        //        //    if (p is GroupPrincipal)
        //        //    {
        //        //        result.Add(p.SamAccountName);
        //        //    }
        //        //}
        //    }

        //    return result;
        //}
        public List<string> GetUserGroups(string username, bool recursive = true)
        {
            ICollection<ILdapEntry> groups = null;// new Collection<LdapEntry>();
            if (!string.IsNullOrWhiteSpace(username))
            {
                var distinguishedName = GetUserByLogonName(username)?.DistinguishedName;
                if (string.IsNullOrWhiteSpace(distinguishedName))
                    throw new Exception($"Invalid user {username}.");
                groups = GetParent(null, distinguishedName, "*", "group", recursive);
            }
            return groups?.Select(x => x.Name).Distinct().ToList();

            //    groups = new List<LdapEntry>();
            //    var filter = $"(&(objectCategory=group)(member={distinguishedName}))";
            //    using (var ldapConnection = this.GetConnection())
            //    {
            //        var search = ldapConnection.Search(
            //        this._searchBase,
            //        LdapConnection.SCOPE_SUB,
            //        filter,
            //        this._attributes,
            //        false,
            //        null,
            //        null);
            //        LdapMessage message;
            //        while ((message = search.getResponse()) != null)
            //        {
            //            if (!(message is LdapSearchResult searchResultMessage))
            //            {
            //                continue;
            //            }
            //            var entry = searchResultMessage.Entry;
            //            groups.Add(this.CreateEntryFromAttributes(entry.DN, entry.getAttributeSet()));
            //            if (!recursive)
            //            {
            //                continue;
            //            }

            //            foreach (var child in this.GetChildren<LdapEntry>(string.Empty, entry.DN))
            //            {
            //                groups.Add(child);
            //            }
            //        }
            //    }
            //}
            //return groups?.Select(x => x.Name).ToList();

            //List<string> groups = null;
            //if (!string.IsNullOrEmpty(username))
            //{
            //    var distinguishedName = GetUserByLogonName(username)?.DistinguishedName;
            //    if (string.IsNullOrWhiteSpace(distinguishedName))
            //        return null;
            //    groups = new List<string>();
            //    var getGroupsFilterForDn = recursive ? $"(&(objectCategory=group)(member:1.2.840.113556.1.4.1941:={distinguishedName}))" : $"(&(objectCategory=group)(member={distinguishedName}))";
            //    using (DirectorySearcher dirSearch = new DirectorySearcher())
            //    {
            //        dirSearch.Filter = getGroupsFilterForDn;
            //        dirSearch.PropertiesToLoad.Add("name");

            //        using (var results = dirSearch.FindAll())
            //        {
            //            foreach (SearchResult result in results)
            //            {
            //                if (result.Properties.Contains("name"))
            //                    groups.Add((string)result.Properties["name"][0]);
            //            }
            //        }
            //    }
            //}
            //return groups;
        }
        public void SetUserAttributes(string username, List<KeyValuePair<string, string>> attributes)
        {
            List<string> result = new List<string>();

            if (string.IsNullOrWhiteSpace(username))
                return;
            var user = GetUserByLogonName(username);
            if (user == null)
                throw new Exception($"User {username} not found.");
            if (attributes?.Count() <= 0)
                return;
            using (var ldapConnection = this.GetConnection())
            {
                var changes = new List<LdapModification>();
                changes.AddRange(attributes.Where(x => !string.IsNullOrWhiteSpace(x.Value)).Select(x => new LdapModification(LdapModification.REPLACE, new LdapAttribute(x.Key, x.Value))).ToList());
                //changes.AddRange(attributes.Where(x => string.IsNullOrWhiteSpace(x.Value)).Select(x => new LdapModification(LdapModification.DELETE, new LdapAttribute(x.Key))).ToList());              
                changes.AddRange(attributes.Where(x => string.IsNullOrWhiteSpace(x.Value)).Select(x => new LdapModification(LdapModification.REPLACE, new LdapAttribute(x.Key, new string[] { }))).ToList());
                ldapConnection.Modify(user.DistinguishedName, changes.ToArray());
            }
        }
        public void ChangeOU(string username, string ouDistinguishedName)
        {
            if (string.IsNullOrWhiteSpace(username))
                throw new Exception("Username cannot be empty.");
            if (string.IsNullOrWhiteSpace(ouDistinguishedName))
                throw new Exception($"OU cannot be empty.");

            var user = GetUserByLogonName(username);
            if (user == null)
                throw new Exception($"Cannot find user {username}.");
            using (var ldapConnection = this.GetConnection())
            {
                ldapConnection.Rename($"{user.DistinguishedName}", $"CN={user.CommonName}", ouDistinguishedName, true);
            }
        }
        public string GetParentOU(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                throw new Exception("Username cannot be empty.");
            var user = GetUserByLogonName(username);
            if (user == null)
                throw new Exception($"Cannot find user {username}.");
            string pattern = @".+?,OU=(.+?),(?:OU|DC)=.+";
            // Create a Regex  
            var regex = new Regex(pattern);
            string result = null;
            var match = regex.Match(user.DistinguishedName);
            if (match.Success)
                result = match.Groups[1].Value;
            return result;
        }
        public void DisableAccount(string username, bool disable)
        {
            var user = GetUserByLogonName(username);
            if (user == null)
                throw new Exception($"User {username} not found.");
            var flag = Convert.ToInt32(user.AccountFlag);
            flag = disable ? flag | 0x2 : flag & ~0x2;
            SetUserAttributes(username, new List<KeyValuePair<string, string>> { new KeyValuePair<string, string>("userAccountControl", flag.ToString()) });
        }
        public ICollection<LdapEntry> GetComputers(string name, string container = null)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException(nameof(name));
            var items = new Collection<LdapEntry>();

            var filter = $"(&(objectClass=Computer)(cn={Microsoft.Security.Application.Encoder.LdapFilterEncode(name)}))";

            using (var ldapConnection = this.GetConnection())
            {
                var search = ldapConnection.Search(
                container ?? this._searchBase,
                LdapConnection.SCOPE_SUB,
                filter,
                this._attributes,
                false,
                null,
                null);

                LdapMessage message;

                while ((message = search.getResponse()) != null)
                {
                    if (!(message is LdapSearchResult searchResultMessage))
                    {
                        continue;
                    }

                    var entry = searchResultMessage.Entry;

                    items.Add(this.CreateEntryFromAttributes(entry.DN, entry.getAttributeSet()));
                }
            }

            return items;
        }
        public void Delete(string name, LdapPrincipalType type = LdapPrincipalType.User)
        {
            string distinguuishedName = null;
            switch (type)
            {
                case LdapPrincipalType.Computer:
                    if (GetComputers(name)?.Count != 1)
                        throw new Exception("Restricted to delete one item each call.");
                    distinguuishedName = GetComputers(name)?.FirstOrDefault()?.DistinguishedName;
                    break;
                case LdapPrincipalType.Group:
                    if (GetGroups(name)?.Count != 1)
                        throw new Exception("Restricted to delete one item each call.");
                    distinguuishedName = GetGroups(name)?.FirstOrDefault()?.DistinguishedName;
                    break;
                case LdapPrincipalType.User:
                    distinguuishedName = GetUserByLogonName(name)?.DistinguishedName;
                    break;
            }
            if (string.IsNullOrWhiteSpace(distinguuishedName))
                throw new Exception($"Invalid name {name}.");
            using (var ldapConnection = this.GetConnection())
            {
                ldapConnection.Delete(distinguuishedName);
            }
        }
        //public List<string> GetComputers(string name, string container=null)
        //{
        //    PrincipalContext ctx = new PrincipalContext(ContextType.Domain, _ldapSettings.ServerName + ":" + _ldapSettings.ServerPort, container ??= _ldapSettings.DomainDistinguishedName, _ldapSettings.UseSSL ? ContextOptions.SimpleBind | ContextOptions.SecureSocketLayer : ContextOptions.Negotiate | ContextOptions.Signing | ContextOptions.Sealing, _ldapSettings.Credentials.DomainUserName, _encryptionService.Decrypt(_ldapSettings.Credentials.Password));
        //    ComputerPrincipal computerPrincipal = new ComputerPrincipal(ctx);

        //    computerPrincipal.Name = name;

        //    PrincipalSearcher ps = new PrincipalSearcher();
        //    if (!string.IsNullOrWhiteSpace(name))
        //        ps.QueryFilter = computerPrincipal;

        //    PrincipalSearchResult<Principal> result = ps.FindAll();
        //    return result?.Select(x => x.SamAccountName).ToList();
        //}
        //public ICollection<UserPrincipal> GetUsersInGroup(string group, bool recursive = false, string container = null)
        //{
        //    return this.GetUsersInGroup(this.GetGroups(group), recursive, container);
        //}

        //public ICollection<UserPrincipal> GetUsersInGroup(ICollection<LdapEntry> groups, bool recursive = false, string container = null)
        //{
        //    var users = new Collection<UserPrincipal>();

        //    if (groups == null || !groups.Any())
        //    {
        //        return null;
        //    }
        //    else
        //    {
        //        foreach (var group in groups)
        //        {
        //            using (var principalContext = new PrincipalContext(ContextType.Domain, _ldapSettings.ServerName + ":" + _ldapSettings.ServerPort, container ??= _ldapSettings.DomainDistinguishedName, _ldapSettings.UseSSL ? ContextOptions.SimpleBind | ContextOptions.SecureSocketLayer : ContextOptions.Negotiate | ContextOptions.Signing | ContextOptions.Sealing, _ldapSettings.Credentials.DomainUserName, _encryptionService.Decrypt(_ldapSettings.Credentials.Password)))
        //            using (var groupPrincipal = GroupPrincipal.FindByIdentity(principalContext, group.DistinguishedName))
        //            {
        //                if (groupPrincipal == null)
        //                    continue;
        //                else
        //                {
        //                    users.AddRange(groupPrincipal.GetMembers(recursive).Select(x => (UserPrincipal)x));
        //                }
        //            }
        //        }
        //    }
        //    return users;
        //}
        private string ConvertToString(sbyte[] sbyteData)
        {
            if (sbyteData?.Length <= 0)
                return null;
            byte[] byteData = Array.ConvertAll(sbyteData, (a) => (byte)a);
            return new Guid(byteData).ToString();
        }
        //private UserPrincipal GetUserPrincipal(string username)
        //{
        //    PrincipalContext ctx = new PrincipalContext(ContextType.Domain, _ldapSettings.ServerName + ":" + _ldapSettings.ServerPort, _ldapSettings.DomainDistinguishedName, _ldapSettings.UseSSL ? ContextOptions.SimpleBind | ContextOptions.SecureSocketLayer : ContextOptions.Negotiate | ContextOptions.Signing | ContextOptions.Sealing, _ldapSettings.Credentials.DomainUserName, _encryptionService.Decrypt(_ldapSettings.Credentials.Password));
        //    UserPrincipal user = UserPrincipal.FindByIdentity(ctx, username.Trim());
        //    return user;
        //}
    }
}