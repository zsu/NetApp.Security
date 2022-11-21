using System;
using System.Collections.Generic;
using System.IO;

namespace NetApp.Security
{
    public interface ILdapService
    {
        ICollection<LdapEntry> GetGroups(string groupName, bool getChildGroups = false);

        ICollection<LdapUser> GetUsersInGroup(string groupName, string container = null);

        ICollection<LdapUser> GetUsersInGroups(ICollection<LdapEntry> groups = null, string container = null);

        ICollection<LdapUser> GetUsersByEmailAddress(string emailAddress);

        ICollection<LdapUser> GetAllUsers(string container=null);

        //LdapUser GetAdministrator();

        ICollection<LdapUser> GetUserByName(string name);
        LdapUser GetUserByLogonName(string username);
        List<LdapUser> GetUser(string firstname, string lastname);
        List<LdapUser> GetSubordinates(string managerUsername);
        LdapUser GetUserByGuid(string guid, string container = null);
        LdapEntry GetByGuid(string guid, string container = null);
        string GetUserAttribute(string username, string attribute, string container = null);
        void AddUser(LdapUser user, string password);
        void Delete(string name, LdapPrincipalType type = LdapPrincipalType.User);
        //void DeleteUser(string distinguishedName);

        bool Authenticate(string distinguishedName, string password);
        void ChangePassword(string username, string password, bool forceChange = true);
        bool IsUserInGroup(string username, List<string> groups, bool checkNested = true);
        void AddToGroups(string username, List<string> groups);
        void RemoveFromGroups(string username, List<string> groups);
        List<string> GetUserGroups(string username, bool recursive = true);
        void SetUserAttributes(string username, List<KeyValuePair<string, string>> attributes);
        ICollection<LdapEntry> GetComputers(string name, string container = null);
        string GetParentOU(string username);
        void DisableAccount(string username, bool disable);
        void SetManager(string username, string managerName);
        void SetPasswordNeverExpires(string username, bool neverExpire);
        void SetPasswordExpired(string username, bool expired = true);
        void ChangeOU(string username, string ouDistinguishedName);
    }
}