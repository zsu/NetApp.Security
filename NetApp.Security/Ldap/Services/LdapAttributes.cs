﻿namespace NetApp.Security
{
    public static class LdapAttributes
    {
        //domain
        public const string Dc = "dc";
        public const string SubRefs = "subRefs";

        //common
        public const string Cn = "cn";
        public const string DistinguishedName = "distinguishedName";
        public const string NtSecurityDescriptor = "nTSecurityDescriptor";
        public const string Name = "name";
        public const string ObjectClass = "objectClass";
        public const string ObjectCategory = "objectCategory";
        public const string IpaUniqueID = "ipaUniqueID";
        public const string ObjectGuid = "objectGUID";
        public const string ObjectSid = "objectSid";
        public const string WhenChanged = "whenChanged";
        public const string ModifyTimestamp = "modifyTimestamp";

        //unit
        public const string Ou = "ou";
        public const string ManagedBy = "managedBy";

        //user
        public const string SAmAccountName = "sAMAccountName";
        public const string Sn = "sn";
        public const string Uid = "uid";
        public const string GivenName = "givenName";
        public const string MiddleName = "middleName";
        public const string DisplayName = "displayName";
        public const string Mail = "mail";
        public const string Fax = "facsimileTelephoneNumber";
        public const string Mobile = "mobile";
        public const string IpPhone = "IpPhone";
        public const string HomePhone = "homePhone";
        public const string TelephoneNumber = "telephoneNumber";
        public const string MemberOf = "memberOf";
        public const string Title = "title";
        public const string Manager = "manager";
        public const string UserAccountControl = "userAccountControl";
        public const string PrimaryGroupID = "primaryGroupID";
        public const string UserPrincipalName = "userPrincipalName";
        public const string Department = "department";
        public const string Division = "division";
        public const string JpegPhoto = "jpegPhoto";
        public const string ThumbnailPhoto = "thumbnailPhoto";
        public const string Description = "description";
        public const string StreetAddress = "streetAddress";
        public const string PostalCode = "postalCode";
        public const string City = "l";
        public const string State = "st";
        public const string Country = "co";
        public const string CountryCode = "c";
        public const string EmployeeId = "employeeID";
        public const string Initials = "initials";
        public const string InstanceType = "instanceType";
        public const string UnicodePwd = "unicodePwd";
        public const string SAMAccountType = "sAMAccountType";
        public const string PwdLastSet = "pwdLastSet";
        public const string EmployeeType = "employeeType";
    }
}