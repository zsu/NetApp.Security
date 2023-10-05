using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Principal;
using System.Text;
using NetApp.Security.Extensions;
using NetApp.Common;
using System.Text.RegularExpressions;
using System.DirectoryServices.Protocols;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Utilities;
using System.ComponentModel;

namespace NetApp.Security
{
    public class LdapService : ILdapService
    {
        protected readonly string _searchBase;

        protected readonly LdapSettings _ldapSettings;
        protected readonly IEncryptionService _encryptionService;

        protected readonly string[] _attributes =
        {
          LdapAttributes.ObjectSid,LdapAttributes.ObjectGuid,LdapAttributes.ObjectCategory,LdapAttributes.ObjectClass,LdapAttributes.MemberOf,
          LdapAttributes.Name,LdapAttributes.Cn,LdapAttributes.DistinguishedName,LdapAttributes.SAmAccountName,LdapAttributes.UserPrincipalName,
          LdapAttributes.DisplayName,LdapAttributes.GivenName,LdapAttributes.Sn,LdapAttributes.Description,LdapAttributes.TelephoneNumber,
          LdapAttributes.Mail,LdapAttributes.StreetAddress,LdapAttributes.PostalCode,LdapAttributes.City,LdapAttributes.State,LdapAttributes.Country,
          LdapAttributes.CountryCode,LdapAttributes.Department,LdapAttributes.Division,LdapAttributes.Manager,LdapAttributes.Title,LdapAttributes.UserAccountControl,
          LdapAttributes.EmployeeId,LdapAttributes.Initials,LdapAttributes.EmployeeType
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
        public LdapService(LdapSettings settings)
        {
            this._ldapSettings = settings;
            this._searchBase = this._ldapSettings.SearchBase;
        }
        public LdapService(LdapSettings ldapSettings, IEncryptionService encryptionService)
        {
            this._ldapSettings = ldapSettings;
            this._searchBase = this._ldapSettings.SearchBase;
            _encryptionService = encryptionService;
        }
        protected LdapConnection GetConnection()
        {
            var identifier = new LdapDirectoryIdentifier(_ldapSettings.ServerName, _ldapSettings.ServerPort);
            var ldapConnection = new LdapConnection(identifier);// { SecureSocketLayer = this._ldapSettings.UseSSL };
            if (!_ldapSettings.ReferralFollowing)
                ldapConnection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
            ldapConnection.SessionOptions.SecureSocketLayer = _ldapSettings.UseSSL;
            ldapConnection.Bind(new System.Net.NetworkCredential(this._ldapSettings.Credentials.DomainUserName, _encryptionService != null ? _encryptionService.Decrypt(this._ldapSettings.Credentials.Password) : this._ldapSettings.Credentials.Password));
            return ldapConnection;
        }

        public ICollection<LdapEntry> GetGroups(string groupName, bool getChildGroups = false)
        {
            var groups = new Collection<LdapEntry>();
            var filter = $"(&(objectClass=group)(cn={LdapEncoder.FilterEncode(groupName)}))";

            using (var ldapConnection = this.GetConnection())
            {
                var result = PagingHandler(_searchBase, filter, SearchScope.Subtree, _attributes);
                foreach (SearchResultEntry entry in result)
                {
                    groups.Add(this.CreateEntryFromAttributes(entry.DistinguishedName, entry.Attributes));

                    if (!getChildGroups)
                    {
                        continue;
                    }

                    foreach (var child in this.GetChildren<LdapEntry>(string.Empty, entry.DistinguishedName))
                    {
                        groups.Add(child);
                    }
                }
            }
            return groups.DistinctBy(x => x.Name).ToList();
        }

        public ICollection<LdapUser> GetAllUsers(string container = null)
        {
            return this.GetUsersInGroups(null, container);
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
                users.AddRange(this.GetChildren<LdapUser>(string.IsNullOrWhiteSpace(container) ? this._searchBase : container));
            }
            else
            {
                foreach (var group in groups)
                {
                    users.AddRange(this.GetChildren<LdapUser>(string.IsNullOrWhiteSpace(container) ? this._searchBase : container, @group.DistinguishedName));
                }
            }

            return users.DistinctBy(x => x.SamAccountName).ToList();
        }

        public ICollection<LdapUser> GetUsersByEmailAddress(string emailAddress)
        {
            var users = new Collection<LdapUser>();
            var filter = $"(&(objectClass=user)(mail={emailAddress}))";

            using (var ldapConnection = this.GetConnection())
            {
                var result = PagingHandler(_searchBase, filter, SearchScope.Subtree, _attributes);
                foreach (SearchResultEntry entry in result)
                {
                    users.Add(this.CreateUserFromAttributes(entry.DistinguishedName, entry.Attributes));
                }
            }
            return users;
        }

        public ICollection<LdapUser> GetUserByName(string name)
        {
            var users = new Collection<LdapUser>();

            var filter = $"(&(objectClass=user)(name={LdapEncoder.FilterEncode(name)}))";
            using (var ldapConnection = this.GetConnection())
            {
                var result = PagingHandler(_searchBase, filter, SearchScope.Subtree, _attributes);
                foreach (SearchResultEntry entry in result)
                {
                    users.Add(this.CreateUserFromAttributes(entry.DistinguishedName, entry.Attributes));
                }
            }
            return users;
        }
        public LdapUser GetUserByLogonName(string username)
        {
            LdapUser user = null;

            var filter = $"(&(objectClass=user)(sAMAccountName={username?.Trim()}))";

            using (var ldapConnection = this.GetConnection())
            {
                var result = PagingHandler(_searchBase, filter, SearchScope.Subtree, _attributes);
                foreach (SearchResultEntry entry in result)
                {
                    user = this.CreateUserFromAttributes(entry.DistinguishedName, entry.Attributes);
                    break;
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
                var result = PagingHandler(_searchBase, filter, SearchScope.Subtree, _attributes);
                foreach (SearchResultEntry entry in result)
                {
                    user.Add(this.CreateUserFromAttributes(entry.DistinguishedName, entry.Attributes));
                }
            }
            return user;
        }
        public virtual LdapUser GetUserByGuid(string guid, string container = null)
        {
            LdapUser user = null;
            var filter = $"(&(objectClass=user)(objectGUID={ConvertGuidToOctetString(guid)}))";

            using (var ldapConnection = this.GetConnection())
            {
                var result = PagingHandler(string.IsNullOrWhiteSpace(container) ? this._searchBase : container, filter, SearchScope.Subtree, _attributes);
                foreach (SearchResultEntry entry in result)
                {
                    user = this.CreateUserFromAttributes(entry.DistinguishedName, entry.Attributes);
                    break;
                }
            }
            return user;
        }
        public virtual LdapEntry GetByGuid(string guid, string container = null)
        {
            LdapEntry result = null;
            var filter = $"(&(objectClass=*)(objectGUID={ConvertGuidToOctetString(guid)}))";

            using (var ldapConnection = this.GetConnection())
            {
                var result1 = PagingHandler(string.IsNullOrWhiteSpace(container) ? this._searchBase : container, filter, SearchScope.Subtree, _attributes);
                foreach (SearchResultEntry entry in result1)
                {
                    result = this.CreateEntryFromAttributes(entry.DistinguishedName, entry.Attributes);
                    break;
                }
            }
            return result;
        }
        public virtual string GetUserAttribute(string username, string attribute, string container = null)
        {
            if (string.IsNullOrWhiteSpace(username))
                return null;
            var filter = $"(&(objectClass=user)(sAMAccountName={username?.Trim()}))";
            using (var ldapConnection = this.GetConnection())
            {
                var result = PagingHandler(string.IsNullOrWhiteSpace(container) ? this._searchBase : container, filter, SearchScope.Subtree, new string[] { attribute });

                foreach (SearchResultEntry entry in result)
                {
                    return GetStringAttribute(entry.Attributes, attribute);
                }
            }
            return null;
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

            AddRequest request = new AddRequest(dn);
            request.Attributes.Add(new DirectoryAttribute(LdapAttributes.InstanceType, "4"));
            request.Attributes.Add(new DirectoryAttribute(LdapAttributes.ObjectCategory, $"CN=Person,CN=Schema,CN=Configuration,{this._ldapSettings.DomainDistinguishedName}"));
            request.Attributes.Add(new DirectoryAttribute(LdapAttributes.ObjectClass, new[] { "top", "person", "organizationalPerson", "user" }));
            request.Attributes.Add(new DirectoryAttribute(LdapAttributes.Name, user.FullName));
            request.Attributes.Add(new DirectoryAttribute(LdapAttributes.Cn, $"{user.FullName}"));
            request.Attributes.Add(new DirectoryAttribute(LdapAttributes.SAmAccountName, user.UserName?.Trim().ToLower()));
            request.Attributes.Add(new DirectoryAttribute(LdapAttributes.UserPrincipalName, $"{user.UserName.Trim().ToLower()}@{this._ldapSettings.DomainName?.Trim()}"));
            request.Attributes.Add(new DirectoryAttribute(LdapAttributes.UnicodePwd, Encoding.Unicode.GetBytes($"\"{user.Password?.Trim()}\"")));
            request.Attributes.Add(new DirectoryAttribute(LdapAttributes.UserAccountControl, user.MustChangePasswordOnNextLogon ? "544" : "512"));
            request.Attributes.Add(new DirectoryAttribute(LdapAttributes.GivenName, user.FirstName?.Trim()));
            request.Attributes.Add(new DirectoryAttribute(LdapAttributes.Sn, user.LastName?.Trim()));

            if (!string.IsNullOrWhiteSpace(user.EmailAddress))
            {
                request.Attributes.Add(new DirectoryAttribute(LdapAttributes.Mail, user.EmailAddress.Trim()));
            }
            if (!string.IsNullOrWhiteSpace(user.DisplayName))
            {
                request.Attributes.Add(new DirectoryAttribute(LdapAttributes.DisplayName, user.DisplayName.Trim()));
            }
            else
                request.Attributes.Add(new DirectoryAttribute(LdapAttributes.DisplayName, user.FullName));
            if (!string.IsNullOrWhiteSpace(user.MiddleName))
            {
                request.Attributes.Add(new DirectoryAttribute(LdapAttributes.Initials, user.MiddleName.Trim()));
            }
            if (!string.IsNullOrWhiteSpace(user.Description))
            {
                request.Attributes.Add(new DirectoryAttribute(LdapAttributes.Description, user.Description.Trim()));
            }
            if (!string.IsNullOrWhiteSpace(user.Phone))
            {
                request.Attributes.Add(new DirectoryAttribute(LdapAttributes.TelephoneNumber, user.Phone.Trim()));
            }
            if (!string.IsNullOrWhiteSpace(user.Address?.Street))
            {
                request.Attributes.Add(new DirectoryAttribute(LdapAttributes.StreetAddress, user.Address.Street.Trim()));
            }
            if (!string.IsNullOrWhiteSpace(user.Address?.City))
            {
                request.Attributes.Add(new DirectoryAttribute(LdapAttributes.City, user.Address.City.Trim()));
            }
            if (!string.IsNullOrWhiteSpace(user.Address?.PostalCode))
            {
                request.Attributes.Add(new DirectoryAttribute(LdapAttributes.PostalCode, user.Address.PostalCode.Trim()));
            }
            if (!string.IsNullOrWhiteSpace(user.Address?.StateName))
            {
                request.Attributes.Add(new DirectoryAttribute(LdapAttributes.State, user.Address.StateName.Trim()));
            }
            if (user.Address?.CountryName != null)
            {
                request.Attributes.Add(new DirectoryAttribute(LdapAttributes.Country, user.Address.CountryName));
            }
            if (!string.IsNullOrWhiteSpace(user.Address?.CountryCode))
            {
                request.Attributes.Add(new DirectoryAttribute(LdapAttributes.CountryCode, user.Address.CountryCode.Trim()));
            }
            if (!string.IsNullOrWhiteSpace(user.EmployeeId))
            {
                request.Attributes.Add(new DirectoryAttribute(LdapAttributes.EmployeeId, user.EmployeeId.Trim()));
            }
            if (!string.IsNullOrWhiteSpace(user.Division))
            {
                request.Attributes.Add(new DirectoryAttribute(LdapAttributes.Division, user.Division.Trim()));
            }
            if (!string.IsNullOrWhiteSpace(user.Department))
            {
                request.Attributes.Add(new DirectoryAttribute(LdapAttributes.Department, user.Department.Trim()));
            }
            if (!string.IsNullOrWhiteSpace(user.Manager))
            {
                var manager = GetUserByLogonName(user.Manager.Trim());
                if (manager == null)
                    throw new Exception($"Invalid manager {user.Manager}.");
                request.Attributes.Add(new DirectoryAttribute(LdapAttributes.Manager, manager.DistinguishedName));
            }
            if (!string.IsNullOrWhiteSpace(user.Title))
            {
                request.Attributes.Add(new DirectoryAttribute(LdapAttributes.Title, user.Title.Trim()));
            }
            if (!string.IsNullOrWhiteSpace(user.EmployeeType))
            {
                request.Attributes.Add(new DirectoryAttribute(LdapAttributes.EmployeeType, user.EmployeeType.Trim()));
            }
            using (var ldapConnection = this.GetConnection())
            {
                var response = ldapConnection.SendRequest(request);
            }
        }

        public bool Authenticate(string username, string password)
        {

            try
            {
                var identifier = new LdapDirectoryIdentifier(_ldapSettings.ServerName, _ldapSettings.ServerPort);
                using (var ldapConnection = new LdapConnection(identifier))
                {
                    if (!_ldapSettings.ReferralFollowing)
                        ldapConnection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
                    ldapConnection.SessionOptions.SecureSocketLayer = _ldapSettings.UseSSL;
                    ldapConnection.Bind(new System.Net.NetworkCredential(username, password));
                }
                return true;
            }
            catch (Exception)
            {
                return false;
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
            var encodedBytes = Encoding.Unicode.GetBytes($"\"{password}\"");
            var attribute = new DirectoryAttributeModification();
            attribute.Operation = DirectoryAttributeOperation.Replace;
            attribute.Name = "unicodePwd";
            attribute.Add(encodedBytes);
            var request = new ModifyRequest(user.DistinguishedName, attribute);
            using (var ldapConnection = this.GetConnection())
            {
                var response = ldapConnection.SendRequest(request);
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

            var filter = $"(&(objectClass=user)(manager={manager.DistinguishedName}))";

            using (var ldapConnection = this.GetConnection())
            {
                var result = PagingHandler(_searchBase, filter, SearchScope.Subtree, _attributes);
                foreach (SearchResultEntry entry in result)
                {
                    user.Add(this.CreateUserFromAttributes(entry.DistinguishedName, entry.Attributes));
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
                entries = this.GetChildren(string.IsNullOrWhiteSpace(searchBase) ? this._searchBase : searchBase, groupDistinguishedName, objectCategory, objectClass, recursive)
                .Cast<T>().ToCollection();
            }

            if (typeof(T) == typeof(LdapUser))
            {
                objectCategory = "person";
                objectClass = "user";
                entries = this.GetChildren(string.IsNullOrWhiteSpace(searchBase) ? this._searchBase : searchBase, groupDistinguishedName, objectCategory, objectClass, recursive).Cast<T>()
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
            : ($"(&(objectCategory={objectCategory})(objectClass={objectClass})(memberOf={groupDistinguishedName}))");

            using (var ldapConnection = this.GetConnection())
            {
                var result = PagingHandler(string.IsNullOrWhiteSpace(searchBase) ? this._searchBase : searchBase, filter, SearchScope.Subtree, _attributes);
                foreach (SearchResultEntry entry in result)
                {
                    if (objectClass == "group")
                    {
                        allChildren.Add(this.CreateEntryFromAttributes(entry.DistinguishedName, entry.Attributes));
                        if (recursive)
                        {
                            foreach (var child in this.GetChildren(searchBase, entry.DistinguishedName, objectCategory, objectClass, recursive))
                            {
                                allChildren.Add(child);
                            }
                        }
                    }
                    if (objectClass == "user")
                        allChildren.Add(this.CreateUserFromAttributes(entry.DistinguishedName, entry.Attributes));
                }
            }
            return allChildren;
        }
        protected virtual ICollection<T> GetParent<T>(string searchBase, string distinguishedName = null, bool recursive = true) where T : ILdapEntry, new()
        {
            var entries = new Collection<T>();

            var objectCategory = "*";
            var objectClass = "*";

            if (typeof(T) == typeof(LdapEntry))
            {
                objectClass = "group";
                objectCategory = "group";
                entries = this.GetParent(string.IsNullOrWhiteSpace(searchBase) ? this._searchBase : searchBase, distinguishedName, objectCategory, objectClass, recursive)
                .Cast<T>().ToCollection();
            }

            if (typeof(T) == typeof(LdapUser))
            {
                objectCategory = "person";
                objectClass = "user";

                entries = this.GetParent(string.IsNullOrWhiteSpace(searchBase) ? this._searchBase : searchBase, distinguishedName, objectCategory, objectClass, recursive).Cast<T>()
                .ToCollection();

            }

            return entries;
        }

        protected virtual ICollection<ILdapEntry> GetParent(string searchBase, string distinguishedName = null,
        string objectCategory = "*", string objectClass = "*", bool recursive = true)
        {
            var allChildren = new Collection<ILdapEntry>();

            var filter = string.IsNullOrEmpty(distinguishedName)
            ? $"(&(objectCategory={objectCategory})(objectClass={objectClass}))"
            : ($"(&(objectCategory={objectCategory})(objectClass={objectClass})(member={distinguishedName}))");
            using (var ldapConnection = this.GetConnection())
            {
                var result = PagingHandler(string.IsNullOrWhiteSpace(searchBase) ? this._searchBase : searchBase, filter, SearchScope.Subtree, _attributes);
                foreach (SearchResultEntry entry in result)
                {
                    if (objectClass == "group")
                    {
                        allChildren.Add(this.CreateEntryFromAttributes(entry.DistinguishedName, entry.Attributes));
                        if (recursive)
                        {
                            foreach (var child in this.GetParent(searchBase, entry.DistinguishedName, objectCategory, objectClass, recursive))
                            {
                                allChildren.Add(child);
                            }
                        }
                    }
                    if (objectClass == "user")
                        allChildren.Add(this.CreateUserFromAttributes(entry.DistinguishedName, entry.Attributes));
                }
            }

            return allChildren;
        }
        protected LdapUser CreateUserFromAttributes(string distinguishedName, SearchResultAttributeCollection attributes)
        {
            var ldapUser = new LdapUser
            {
                ObjectSid = GetStringAttribute(attributes, LdapAttributes.ObjectSid),
                ObjectGuid = ConvertToGuidString(GetByteAttribute(attributes, LdapAttributes.ObjectGuid)),
                ObjectCategory = GetStringAttribute(attributes, LdapAttributes.ObjectCategory),
                ObjectClass = GetStringAttribute(attributes, LdapAttributes.ObjectClass),
                IsDomainAdmin = GetStringArrayAttribute(attributes, LdapAttributes.MemberOf) != null ? GetStringArrayAttribute(attributes, LdapAttributes.MemberOf).Contains("CN=Domain Admins,") : false,
                MemberOf = GetStringArrayAttribute(attributes, LdapAttributes.MemberOf),
                CommonName = GetStringAttribute(attributes, LdapAttributes.Cn),
                UserName = GetStringAttribute(attributes, LdapAttributes.Name),
                SamAccountName = GetStringAttribute(attributes, LdapAttributes.SAmAccountName),
                UserPrincipalName = GetStringAttribute(attributes, LdapAttributes.UserPrincipalName),
                Name = GetStringAttribute(attributes, LdapAttributes.Name),
                DistinguishedName = GetStringAttribute(attributes, LdapAttributes.DistinguishedName),
                DisplayName = GetStringAttribute(attributes, LdapAttributes.DisplayName),
                FirstName = GetStringAttribute(attributes, LdapAttributes.GivenName),
                LastName = GetStringAttribute(attributes, LdapAttributes.Sn),
                Description = GetStringAttribute(attributes, LdapAttributes.Description),
                Phone = GetStringAttribute(attributes, LdapAttributes.TelephoneNumber),
                EmailAddress = GetStringAttribute(attributes, LdapAttributes.Mail),
                Address = new LdapAddress
                {
                    Street = GetStringAttribute(attributes, LdapAttributes.StreetAddress),
                    City = GetStringAttribute(attributes, LdapAttributes.City),
                    PostalCode = GetStringAttribute(attributes, LdapAttributes.PostalCode),
                    StateName = GetStringAttribute(attributes, LdapAttributes.State),
                    CountryName = GetStringAttribute(attributes, LdapAttributes.Country),
                    CountryCode = GetStringAttribute(attributes, LdapAttributes.CountryCode)
                },

                SamAccountType = int.Parse(GetStringAttribute(attributes, LdapAttributes.SAMAccountType) ?? "0"),
                MiddleName = GetStringAttribute(attributes, LdapAttributes.Initials),
                EmployeeId = GetStringAttribute(attributes, LdapAttributes.EmployeeId),
                Title = GetStringAttribute(attributes, LdapAttributes.Title),
                Division = GetStringAttribute(attributes, LdapAttributes.Division),
                Department = GetStringAttribute(attributes, LdapAttributes.Department),
                Manager = GetStringAttribute(attributes, LdapAttributes.Manager),
                AccountFlag = GetStringAttribute(attributes, LdapAttributes.UserAccountControl),
                EmployeeType = GetStringAttribute(attributes, LdapAttributes.EmployeeType),
            };

            return ldapUser;
        }
        protected LdapEntry CreateEntryFromAttributes(string distinguishedName, SearchResultAttributeCollection attributes)
        {
            return new LdapEntry
            {
                ObjectSid = GetStringAttribute(attributes, LdapAttributes.ObjectSid),
                ObjectGuid = ConvertToGuidString(GetByteAttribute(attributes, LdapAttributes.ObjectGuid)),
                ObjectCategory = GetStringAttribute(attributes, LdapAttributes.ObjectCategory),
                ObjectClass = GetStringAttribute(attributes, LdapAttributes.ObjectClass),
                CommonName = GetStringAttribute(attributes, LdapAttributes.Cn),
                Name = GetStringAttribute(attributes, LdapAttributes.Name),
                DistinguishedName = GetStringAttribute(attributes, LdapAttributes.DistinguishedName),
                SamAccountName = GetStringAttribute(attributes, LdapAttributes.SAmAccountName),
                SamAccountType = int.Parse(GetStringAttribute(attributes, LdapAttributes.SAMAccountType) ?? "0"),
            };
        }
        //private SecurityIdentifier GetDomainSid()
        //{
        //    var administratorAcount = new NTAccount(this._ldapSettings.DomainName, "administrator");
        //    var administratorSId = (SecurityIdentifier)administratorAcount.Translate(typeof(SecurityIdentifier));
        //    return administratorSId.AccountDomainSid;
        //}

        //private IEnumerable<string> GetGroupsForUser(string username)
        //{
        //    //var items = _cache?.Get<Dictionary<string, HashSet<string>>>(CacheKeyADGroups);
        //    //var item = items?[userName];
        //    //if (item != null)
        //    //    return item;
        //    //else
        //    //{
        //    var groups = new Stack<string>();
        //    var uniqueGroups = new HashSet<string>();

        //    foreach (string group in this.GetGroupsForUserCore(username))
        //        uniqueGroups.Add(group);

        //    //if (items == null)
        //    //{
        //    //    items = new Dictionary<string, HashSet<string>>();
        //    //    items.Add(userName, uniqueGroups);
        //    //    _cache?.Set(CacheKeyADGroups, items);
        //    //}
        //    //else
        //    //{
        //    //    items.Add(userName, uniqueGroups);
        //    //}
        //    return uniqueGroups;
        //}
        ///// <summary>
        ///// Get nested groups membership for user
        ///// </summary>
        ///// <param name="username"></param>
        // /// <returns></returns>
        //private IEnumerable<string> GetNestedGroupsForUser(string username)
        //{
        //    //var items = _cache?.Get<Dictionary<string, HashSet<string>>>(CacheKeyADGroups);
        //    //var item = items?[username];
        //    //if (item != null)
        //    //    return item;
        //    //else
        //    //{
        //    Dictionary<string, HashSet<string>> items = null;
        //    var groups = new Stack<string>();
        //    var uniqueGroups = new HashSet<string>();

        //    foreach (string group in this.GetGroupsForUserCore(username))
        //        groups.Push(group);

        //    while (groups.Count > 0)
        //    {
        //        string group = groups.Pop();
        //        uniqueGroups.Add(group);

        //        foreach (string parentGroup in this.GetGroupsForUserCore(group))
        //            groups.Push(parentGroup);
        //    }
        //    if (items == null)
        //    {
        //        items = new Dictionary<string, HashSet<string>>();
        //        items.Add(username, uniqueGroups);
        //        //_cache?.Set(CacheKeyADGroups, items);
        //    }
        //    else
        //    {
        //        items.Add(username, uniqueGroups);
        //    }
        //    return uniqueGroups;
        //    //}
        //}

        //private IEnumerable<string> GetGroupsForUserCore(string username)
        //{
        //    using (var ldapConnection = this.GetConnection())
        //    {
        //        var result = PagingHandler(_searchBase, $"(sAMAccountName={username})", SearchScope.Subtree, new string[] { "cn", "memberOf" });
        //        foreach (SearchResultEntry entry in result)
        //        {
        //            foreach (var value in HandleEntry(entry))
        //                yield return value;
        //        }
        //    }
        //}

        //private IEnumerable<string> HandleEntry(SearchResultEntry entry)
        //{
        //    var attr = GetStringArrayAttribute(entry.Attributes, "memberOf");

        //    if (attr == null) yield break;

        //    foreach (string value in attr)
        //    {
        //        string groupName = GetCN(value);
        //        yield return groupName;
        //    }
        //}

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
            foreach (var item in groupsToAdd)
            {
                var groupDn = GetGroups(item)?.FirstOrDefault()?.DistinguishedName;
                if (string.IsNullOrWhiteSpace(groupDn))
                    throw new Exception($"Invalid group {item}.");
                //LdapModification[] modGroup = new LdapModification[1];
                //LdapAttribute member = new LdapAttribute("member", userDn);
                //modGroup[0] = new LdapModification(LdapModification.Add, member);
                //ldapConnection.Modify(groupDn, modGroup);
                var attribute = new DirectoryAttributeModification();
                attribute.Operation = DirectoryAttributeOperation.Add;
                attribute.Name = "member";
                attribute.Add(userDn);
                var request = new ModifyRequest(groupDn, attribute);
                using (var ldapConnection = this.GetConnection())
                {
                    var response = ldapConnection.SendRequest(request);
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
            foreach (var item in groups)
            {
                var groupDn = GetGroups(item)?.FirstOrDefault()?.DistinguishedName;
                if (string.IsNullOrWhiteSpace(groupDn))
                    throw new Exception($"Invalid group {item}.");
                //LdapModification[] modGroup = new LdapModification[1];
                //LdapAttribute member = new LdapAttribute("member", userDn);
                //modGroup[0] = new LdapModification(LdapModification.Delete, member);
                //ldapConnection.Modify(groupDn, modGroup);
                var attribute = new DirectoryAttributeModification();
                attribute.Operation = DirectoryAttributeOperation.Delete;
                attribute.Name = "member";
                attribute.Add(userDn);
                var request = new ModifyRequest(groupDn, attribute);
                using (var ldapConnection = this.GetConnection())
                {
                    var response = ldapConnection.SendRequest(request);
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
        public List<string> GetUserGroups(string username, bool recursive = true, string container = null)
        {
            ICollection<ILdapEntry> groups = null;// new Collection<LdapEntry>();
            if (!string.IsNullOrWhiteSpace(username))
            {
                var distinguishedName = GetUserByLogonName(username)?.DistinguishedName;
                if (string.IsNullOrWhiteSpace(distinguishedName))
                    throw new Exception($"Invalid user {username}.");
                groups = GetParent(container, distinguishedName, "*", "group", recursive);
            }
            return groups?.Select(x => x.Name).Distinct().ToList();
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
            //var changes = new List<LdapModification>();
            //changes.AddRange(attributes.Where(x => !string.IsNullOrWhiteSpace(x.Value)).Select(x => new DirectoryAttributeModification ( DirectoryAttributeOperation.Replace,  new LdapAttribute(x.Key, x.Value) )).ToList());
            //changes.AddRange(attributes.Where(x => string.IsNullOrWhiteSpace(x.Value)).Select(x => new LdapModification(LdapModification.DELETE, new LdapAttribute(x.Key))).ToList());              
            //changes.AddRange(attributes.Where(x => string.IsNullOrWhiteSpace(x.Value)).Select(x => new DirectoryAttributeModification(DirectoryAttributeOperation.Replace, new LdapAttribute(x.Key, new string[] { }))).ToList());
            //ldapConnection.Modify(user.DistinguishedName, changes.ToArray());
            var changes = new List<DirectoryAttributeModification>();
            foreach (var item in attributes)
            {
                var attribute = new DirectoryAttributeModification();
                if (string.IsNullOrWhiteSpace(item.Value))
                {
                    attribute.Operation = DirectoryAttributeOperation.Delete;
                }
                else
                {
                    attribute.Operation = DirectoryAttributeOperation.Replace;
                    attribute.Add(item.Value);
                }
                attribute.Name = item.Key;
                changes.Add(attribute);
            }

            var request = new ModifyRequest(user.DistinguishedName, changes.ToArray());
            using (var ldapConnection = this.GetConnection())
            {
                var response = ldapConnection.SendRequest(request);
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
                //ldapConnection.Rename($"{user.DistinguishedName}", $"CN={user.CommonName}", ouDistinguishedName, true);
                ModifyDNRequest request = new ModifyDNRequest();
                request.DeleteOldRdn = true;
                request.DistinguishedName = user.DistinguishedName;
                request.NewName = $"CN={user.CommonName}";
                request.NewParentDistinguishedName = ouDistinguishedName;
                ModifyDNResponse response = (ModifyDNResponse)ldapConnection.SendRequest(request);
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

            var filter = $"(&(objectClass=Computer)(cn={LdapEncoder.FilterEncode(name)}))";

            using (var ldapConnection = this.GetConnection())
            {
                var result = PagingHandler(string.IsNullOrWhiteSpace(container) ? this._searchBase : container, filter, SearchScope.Subtree, _attributes);
                foreach (SearchResultEntry entry in result)
                {
                    items.Add(this.CreateEntryFromAttributes(entry.DistinguishedName, entry.Attributes));
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
            //ldapConnection.Delete(distinguuishedName);
            var request = new DeleteRequest(distinguuishedName);
            using (var ldapConnection = this.GetConnection())
            {
                var response = ldapConnection.SendRequest(request);
            }
        }
        protected ICollection<SearchResultEntry> PagingHandler(string distinguishedName, string filter, SearchScope searchScope, params string[] attributeList)
        {
            List<SearchResultEntry> result = new List<SearchResultEntry>();
            var request = new SearchRequest(distinguishedName, filter, searchScope, attributeList);
            using (var ldapConnection = GetConnection())
            {
                PageResultRequestControl prc = new PageResultRequestControl(_ldapSettings.PageSize);
                request.Controls.Add(prc);
                while (true)
                {
                    SearchResponse response = ldapConnection.SendRequest(request) as SearchResponse;
                    foreach (DirectoryControl control in response.Controls)
                    {
                        if (control is PageResultResponseControl)
                        {
                            prc.Cookie = ((PageResultResponseControl)control).Cookie;
                            break;
                        }
                    }
                    foreach (SearchResultEntry sre in response.Entries)
                    {
                        result.Add(sre);
                    }
                    if (prc.Cookie.Length == 0)
                        break;
                }
            }
            return result;
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
        private string ConvertToGuidString(byte[] byteData)
        {
            if (byteData?.Length <= 0)
                return null;
            return new Guid(byteData).ToString();
        }
        private string ConvertGuidToOctetString(string objectGuid)
        {
            if (string.IsNullOrWhiteSpace(objectGuid))
                return null;
            var result = new StringBuilder();
            Guid guid = new Guid(objectGuid);
            byte[] byteGuid = guid.ToByteArray();
            foreach (byte b in byteGuid)
            {
                result.Append(@"\" + b.ToString("x2"));
            }
            return result.ToString();
        }
        //private UserPrincipal GetUserPrincipal(string username)
        //{
        //    PrincipalContext ctx = new PrincipalContext(ContextType.Domain, _ldapSettings.ServerName + ":" + _ldapSettings.ServerPort, _ldapSettings.DomainDistinguishedName, _ldapSettings.UseSSL ? ContextOptions.SimpleBind | ContextOptions.SecureSocketLayer : ContextOptions.Negotiate | ContextOptions.Signing | ContextOptions.Sealing, _ldapSettings.Credentials.DomainUserName, _encryptionService.Decrypt(_ldapSettings.Credentials.Password));
        //    UserPrincipal user = UserPrincipal.FindByIdentity(ctx, username.Trim());
        //    return user;
        //}
        private sbyte[] ToSByteArray(byte[] byteArray)
        {
            var sbyteArray = new sbyte[byteArray.Length];
            for (var index = 0; index < byteArray.Length; index++)
                sbyteArray[index] = (sbyte)byteArray[index];
            return sbyteArray;
        }
        private string GetStringAttribute(SearchResultAttributeCollection attributes, string key)
        {
            if (attributes == null || !attributes.Contains(key))
            {
                return null;
            }
            string[] rawVal = (string[])attributes[key].GetValues(typeof(string));
            return rawVal[0];
        }
        private byte[] GetByteAttribute(SearchResultAttributeCollection attributes, string key)
        {
            if (attributes == null || !attributes.Contains(key))
            {
                return null;
            }
            byte[] bva = null;
            if (attributes[key] != null)
            {
                // Deep copy so app can't change the value
                bva = new byte[((byte[])attributes[key][0]).Length];
                Array.Copy((Array)attributes[key][0], 0, bva, 0, bva.Length);
            }

            return bva;
        }
        private string[] GetStringArrayAttribute(SearchResultAttributeCollection attributes, string key)
        {
            if (attributes == null || !attributes.Contains(key))
            {
                return null;
            }

            //var size = attributes[key].Count;
            //var sva = new string[size];
            //for (var j = 0; j < size; j++)
            //{
            //    var valueBytes = (byte[])attributes[key][j];
            //    sva[j] = valueBytes != null && valueBytes?.Length > 0 ? Encoding.UTF8.GetString(valueBytes) : string.Empty;
            //}

            //return sva;
            return (string[])attributes[key].GetValues(typeof(string));
        }
    }
}