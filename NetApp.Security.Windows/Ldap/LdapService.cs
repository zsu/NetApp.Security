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
using System.IO;
using System.DirectoryServices.Protocols;
using System.ComponentModel;

namespace NetApp.Security.Windows
{
    public class LdapService : NetApp.Security.LdapService, ILdapService
    {
        public LdapService(IOptions<LdapSettings> ldapSettings) : base(ldapSettings)
        { }
        public LdapService(IOptions<LdapSettings> ldapSettingsOptions, IEncryptionService encryptionService) : base(ldapSettingsOptions, encryptionService)
        { }
        public LdapService(LdapSettings settings) : base(settings)
        { }
        public LdapService(LdapSettings ldapSettings, IEncryptionService encryptionService) : base(ldapSettings, encryptionService)
        { }
        public void UpdatePhoto(string username, Stream stream)
        {
            int size = 96;
            if (string.IsNullOrWhiteSpace(username))
                throw new ArgumentNullException(nameof(username));
            var user = GetUserByLogonName(username);
            if (user == null)
                throw new Exception($"User {username} not found.");
            byte[] bytes;
            using (var ms = new MemoryStream())
            {
                stream.CopyTo(ms);
                bytes = ms.ToArray();
            }
            //var changes = new LdapModification(LdapModification.Replace, new LdapAttribute("jpegPhoto", bytes));
            //using (var ldapConnection = this.GetConnection())
            //{
            //    ldapConnection.Modify(user.DistinguishedName, changes);
            //}
            var attribute = new DirectoryAttributeModification();
            attribute.Operation = DirectoryAttributeOperation.Replace;
            attribute.Name = "jpegPhoto";
            attribute.Add(bytes);
            var request = new ModifyRequest(user.DistinguishedName, attribute);
            using (var ldapConnection = this.GetConnection())
            {
                var response = ldapConnection.SendRequest(request);
            }
            System.Drawing.Image img = System.Drawing.Image.FromStream(stream);

            if (img.Size.Width > size || img.Size.Height > size)
            {
                System.Drawing.Image resized = ResizeImage(img, new System.Drawing.Size(size, size));
                using (var ms = new MemoryStream())
                {
                    resized.Save(ms, System.Drawing.Imaging.ImageFormat.Bmp);
                    bytes = ms.ToArray();
                }
            }
            //changes = new LdapModification(LdapModification.Replace, new LdapAttribute("thumbnailPhoto", bytes));
            //using (var ldapConnection = this.GetConnection())
            //{
            //    ldapConnection.Modify(user.DistinguishedName, changes);
            //}
            attribute = new DirectoryAttributeModification();
            attribute.Operation = DirectoryAttributeOperation.Replace;
            attribute.Name = "thumbnailPhoto";
            attribute.Add(bytes);
            request = new ModifyRequest(user.DistinguishedName, attribute);
            using (var ldapConnection = this.GetConnection())
            {
                var response = ldapConnection.SendRequest(request);
            }
            //using (var img = Image.FromStream(stream))
            //{
            //    ImageConverter converter = new ImageConverter();
            //    byte[] bytes = (byte[])converter.ConvertTo(img, typeof(byte[]));
            //    var changes = new LdapModification(LdapModification.REPLACE, new LdapAttribute("jpegPhoto", SupportClass.ToSByteArray(bytes)));
            //    using (var ldapConnection = this.GetConnection())
            //    {
            //        ldapConnection.Modify(user.DistinguishedName, changes);
            //    }
            //}
        }
        protected override ICollection<T> GetChildren<T>(string searchBase, string groupDistinguishedName = null, bool recursive = true)
        {
            if (string.IsNullOrEmpty(groupDistinguishedName))
            {
                return new Collection<T>();
            }

            var entries = new Collection<T>();
            string filter;

            if (typeof(T) == typeof(LdapEntry))
            {
                // For groups, use LDAP_MATCHING_RULE_IN_CHAIN if recursive
                filter = recursive
                    ? $"(&(objectCategory=group)(objectClass=group)(memberOf:1.2.840.113556.1.4.1941:={groupDistinguishedName}))"
                    : $"(&(objectCategory=group)(objectClass=group)(memberOf={groupDistinguishedName}))";
            }
            else if (typeof(T) == typeof(LdapUser))
            {
                // For users, use LDAP_MATCHING_RULE_IN_CHAIN if recursive
                filter = recursive
                    ? $"(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={groupDistinguishedName}))"
                    : $"(&(objectCategory=person)(objectClass=user)(memberOf={groupDistinguishedName}))";
            }
            else
            {
                return entries;
            }

            using (var ldapConnection = this.GetConnection())
            {
                // Use range retrieval for better performance with large groups
                var rangeAttributes = new List<string>(_attributes);
                if (!rangeAttributes.Contains("member;range=0-1499"))
                {
                    rangeAttributes.Add("member;range=0-1499");
                }

                var result = PagingHandler(
                    string.IsNullOrWhiteSpace(searchBase) ? this._searchBase : searchBase,
                    filter,
                    SearchScope.Subtree,
                    rangeAttributes.ToArray());

                foreach (SearchResultEntry entry in result)
                {
                    if (typeof(T) == typeof(LdapEntry) && entry.Attributes["objectClass"].Contains("group"))
                    {
                        entries.Add((T)(object)this.CreateEntryFromAttributes(entry.DistinguishedName, entry.Attributes));
                    }
                    else if (typeof(T) == typeof(LdapUser) && entry.Attributes["objectClass"].Contains("user"))
                    {
                        entries.Add((T)(object)this.CreateUserFromAttributes(entry.DistinguishedName, entry.Attributes));
                    }
                }
            }

            return entries;
        }

        protected override ICollection<ILdapEntry> GetChildren(string searchBase, string groupDistinguishedName = null,
        string objectCategory = "*", string objectClass = "*", bool recursive = true)
        {
            if (string.IsNullOrEmpty(groupDistinguishedName))
            {
                return new HashSet<ILdapEntry>();
            }

            var allChildren = new HashSet<ILdapEntry>();

            // Use LDAP_MATCHING_RULE_IN_CHAIN for recursive searches
            var filter = recursive
                ? $"(&(objectCategory={objectCategory})(objectClass={objectClass})(memberOf:1.2.840.113556.1.4.1941:={groupDistinguishedName}))"
                : $"(&(objectCategory={objectCategory})(objectClass={objectClass})(memberOf={groupDistinguishedName}))";

            using (var ldapConnection = this.GetConnection())
            {
                // Use range retrieval for better performance with large groups
                var rangeAttributes = new List<string>(_attributes);
                if (!rangeAttributes.Contains("member;range=0-1499"))
                {
                    rangeAttributes.Add("member;range=0-1499");
                }

                var result = PagingHandler(
                    string.IsNullOrWhiteSpace(searchBase) ? this._searchBase : searchBase,
                    filter,
                    SearchScope.Subtree,
                    rangeAttributes.ToArray());

                foreach (SearchResultEntry entry in result)
                {
                    if (objectClass == "group" && entry.Attributes["objectClass"].Contains("group"))
                    {
                        allChildren.Add(this.CreateEntryFromAttributes(entry.DistinguishedName, entry.Attributes));
                    }
                    else if (objectClass == "user" && entry.Attributes["objectClass"].Contains("user"))
                    {
                        allChildren.Add(this.CreateUserFromAttributes(entry.DistinguishedName, entry.Attributes));
                    }
                }
            }

            return allChildren;
        }
        protected override ICollection<T> GetParent<T>(string searchBase, string distinguishedName = null, bool recursive = true)
        {
            if (!recursive)
            {
                return base.GetParent<T>(searchBase, distinguishedName, false);
            }

            var entries = new Collection<T>();
            if (string.IsNullOrEmpty(distinguishedName))
            {
                return entries;
            }

            using (var ldapConnection = this.GetConnection())
            {
                // First get the tokenGroups for the specified distinguishedName
                var tokenGroupsFilter = $"(&(distinguishedName={distinguishedName}))";
                var tokenGroupsResult = PagingHandler(string.IsNullOrWhiteSpace(searchBase) ? this._searchBase : searchBase, 
                    tokenGroupsFilter, SearchScope.Subtree, new[] { "tokenGroups", "objectClass" });

                foreach (SearchResultEntry entry in tokenGroupsResult)
                {
                    var tokenGroups = entry.Attributes["tokenGroups"];
                    if (tokenGroups != null)
                    {
                        // Build an OR filter for all SIDs
                        var sidFilters = new List<string>();
                        foreach (byte[] sidBytes in tokenGroups)
                        {
                            var sid = new SecurityIdentifier(sidBytes, 0).ToString();
                            sidFilters.Add($"(objectSid={sid})");
                        }

                        if (sidFilters.Count > 0)
                        {
                            string filter;
                            if (typeof(T) == typeof(LdapEntry))
                            {
                                filter = $"(&(objectCategory=group)(objectClass=group)(|{string.Join("", sidFilters)}))";
                            }
                            else if (typeof(T) == typeof(LdapUser))
                            {
                                filter = $"(&(objectCategory=person)(objectClass=user)(|{string.Join("", sidFilters)}))";
                            }
                            else
                            {
                                return entries;
                            }

                            var result = PagingHandler(string.IsNullOrWhiteSpace(searchBase) ? this._searchBase : searchBase, 
                                filter, SearchScope.Subtree, _attributes);

                            foreach (SearchResultEntry groupEntry in result)
                            {
                                if (typeof(T) == typeof(LdapEntry) && groupEntry.Attributes["objectClass"].Contains("group"))
                                {
                                    entries.Add((T)(object)this.CreateEntryFromAttributes(groupEntry.DistinguishedName, groupEntry.Attributes));
                                }
                                else if (typeof(T) == typeof(LdapUser) && groupEntry.Attributes["objectClass"].Contains("user"))
                                {
                                    entries.Add((T)(object)this.CreateUserFromAttributes(groupEntry.DistinguishedName, groupEntry.Attributes));
                                }
                            }
                        }
                    }
                }
            }

            return entries;
        }

        protected override ICollection<ILdapEntry> GetParent(string searchBase, string distinguishedName = null,
        string objectCategory = "*", string objectClass = "*", bool recursive = true)
        {
            if (!recursive)
            {
                return base.GetParent(searchBase, distinguishedName, objectCategory, objectClass, false);
            }

            if (string.IsNullOrEmpty(distinguishedName))
            {
                return new HashSet<ILdapEntry>();
            }

            var allChildren = new HashSet<ILdapEntry>();
            
            using (var ldapConnection = this.GetConnection())
            {
                // Get tokenGroups for the specified distinguishedName
                var tokenGroupsFilter = $"(&(distinguishedName={distinguishedName}))";
                var tokenGroupsResult = PagingHandler(string.IsNullOrWhiteSpace(searchBase) ? this._searchBase : searchBase, 
                    tokenGroupsFilter, SearchScope.Subtree, new[] { "tokenGroups", "objectClass" });

                foreach (SearchResultEntry entry in tokenGroupsResult)
                {
                    var tokenGroups = entry.Attributes["tokenGroups"];
                    if (tokenGroups != null)
                    {
                        // Build an OR filter for all SIDs
                        var sidFilters = new List<string>();
                        foreach (byte[] sidBytes in tokenGroups)
                        {
                            var sid = new SecurityIdentifier(sidBytes, 0).ToString();
                            sidFilters.Add($"(objectSid={sid})");
                        }

                        if (sidFilters.Count > 0)
                        {
                            // Add object class and category filters
                            var classFilter = objectClass == "*" ? "(|(objectClass=group)(objectClass=user))" 
                                : $"(objectClass={objectClass})";
                            var categoryFilter = objectCategory == "*" ? "" 
                                : $"(objectCategory={objectCategory})";

                            var filter = $"(&{classFilter}{categoryFilter}(|{string.Join("", sidFilters)}))";
                            var result = PagingHandler(string.IsNullOrWhiteSpace(searchBase) ? this._searchBase : searchBase, 
                                filter, SearchScope.Subtree, _attributes);

                            foreach (SearchResultEntry groupEntry in result)
                            {
                                if (groupEntry.Attributes["objectClass"].Contains("group"))
                                {
                                    allChildren.Add(this.CreateEntryFromAttributes(groupEntry.DistinguishedName, groupEntry.Attributes));
                                }
                                else if (groupEntry.Attributes["objectClass"].Contains("user"))
                                {
                                    allChildren.Add(this.CreateUserFromAttributes(groupEntry.DistinguishedName, groupEntry.Attributes));
                                }
                            }
                        }
                    }
                }
            }

            return allChildren;
        }
        private System.Drawing.Image ResizeImage(System.Drawing.Image image, System.Drawing.Size size, bool preserveAspectRatio = true)
        {
            int newWidth;
            int newHeight;
            if (preserveAspectRatio)
            {
                int originalWidth = image.Width;
                int originalHeight = image.Height;
                float percentWidth = (float)size.Width / (float)originalWidth;
                float percentHeight = (float)size.Height / (float)originalHeight;
                float percent = percentHeight < percentWidth ? percentHeight : percentWidth;
                newWidth = (int)(originalWidth * percent);
                newHeight = (int)(originalHeight * percent);
            }
            else
            {
                newWidth = size.Width;
                newHeight = size.Height;
            }
            System.Drawing.Image newImage = new System.Drawing.Bitmap(newWidth, newHeight);
            using (System.Drawing.Graphics graphicsHandle = System.Drawing.Graphics.FromImage(newImage))
            {
                graphicsHandle.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;
                graphicsHandle.DrawImage(image, 0, 0, newWidth, newHeight);
            }
            return newImage;
        }
    }
}