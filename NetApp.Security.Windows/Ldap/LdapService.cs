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
                filter = recursive
                    ? $"(&(objectCategory=group)(objectClass=group)(memberOf:1.2.840.113556.1.4.1941:={groupDistinguishedName}))"
                    : $"(&(objectCategory=group)(objectClass=group)(memberOf={groupDistinguishedName}))";
            }
            else if (typeof(T) == typeof(LdapUser))
            {
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
                    if (typeof(T) == typeof(LdapEntry) && ContainsValueInAttribute(entry.Attributes["objectClass"], "group"))
                    {
                        entries.Add((T)(object)this.CreateEntryFromAttributes(entry.DistinguishedName, entry.Attributes));
                    }
                    else if (typeof(T) == typeof(LdapUser) && ContainsValueInAttribute(entry.Attributes["objectClass"], "user"))
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
            var filter = recursive
                ? $"(&(objectCategory={objectCategory})(objectClass={objectClass})(memberOf:1.2.840.113556.1.4.1941:={groupDistinguishedName}))"
                : $"(&(objectCategory={objectCategory})(objectClass={objectClass})(memberOf={groupDistinguishedName}))";

            using (var ldapConnection = this.GetConnection())
            {
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
                    if (objectClass == "group" && ContainsValueInAttribute(entry.Attributes["objectClass"], "group"))
                    {
                        allChildren.Add(this.CreateEntryFromAttributes(entry.DistinguishedName, entry.Attributes));
                    }
                    else if (objectClass == "user" && ContainsValueInAttribute(entry.Attributes["objectClass"], "user"))
                    {
                        allChildren.Add(this.CreateUserFromAttributes(entry.DistinguishedName, entry.Attributes));
                    }
                }
            }

            return allChildren;
        }
        protected override ICollection<T> GetParent<T>(string searchBase, string distinguishedName = null, bool recursive = true)
        {
            var entries = new Collection<T>();

            if (string.IsNullOrEmpty(distinguishedName))
            {
                return entries;
            }

            using (var ldapConnection = this.GetConnection())
            {
                try
                {
                    var tokenGroupsFilter = "(objectClass=*)";
                    var tokenGroupsResult = PagingHandler(distinguishedName, tokenGroupsFilter, SearchScope.Base, new[] { "tokenGroups", "objectClass" });
                    
                    foreach (SearchResultEntry entry in tokenGroupsResult)
                    {
                        var tokenGroups = entry.Attributes["tokenGroups"];
                        if (tokenGroups != null)
                        {
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
                                    if (typeof(T) == typeof(LdapEntry) && groupEntry.Attributes.Contains("objectClass"))
                                    {
                                        var objectClasses = groupEntry.Attributes["objectClass"];
                                        bool isGroup = false;
                                        isGroup = ContainsValueInAttribute(objectClasses, "group");
                                        if (!isGroup)
                                        {
                                            foreach (string val in objectClasses.GetValues(typeof(string)))
                                            {
                                                if (string.Equals(val, "group", StringComparison.OrdinalIgnoreCase))
                                                {
                                                    isGroup = true;
                                                    break;
                                                }
                                            }
                                        }
                                        
                                        if (isGroup)
                                        {
                                            entries.Add((T)(object)this.CreateEntryFromAttributes(groupEntry.DistinguishedName, groupEntry.Attributes));
                                        }
                                    }
                                    else if (typeof(T) == typeof(LdapUser) && groupEntry.Attributes.Contains("objectClass"))
                                    {
                                        var objectClasses = groupEntry.Attributes["objectClass"];
                                        bool isUser = false;                                        
                                        isUser = ContainsValueInAttribute(objectClasses, "user");                                        
                                        if (!isUser)
                                        {
                                            foreach (string val in objectClasses.GetValues(typeof(string)))
                                            {
                                                if (string.Equals(val, "user", StringComparison.OrdinalIgnoreCase))
                                                {
                                                    isUser = true;
                                                    break;
                                                }
                                            }
                                        }
                                        
                                        if (isUser)
                                        {
                                            entries.Add((T)(object)this.CreateUserFromAttributes(groupEntry.DistinguishedName, groupEntry.Attributes));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                catch (DirectoryOperationException ex)
                {
                    string objectCategory;
                    string objectClass;

                    if (typeof(T) == typeof(LdapEntry))
                    {
                        objectClass = "group";
                        objectCategory = "group";
                    }
                    else if (typeof(T) == typeof(LdapUser))
                    {
                        objectCategory = "person";
                        objectClass = "user";
                    }
                    else
                    {
                        return entries;
                    }
                    var getGroupsFilter = recursive ? 
                        $"(&(objectCategory={objectCategory})(objectClass={objectClass})(member:1.2.840.113556.1.4.1941:={distinguishedName}))" : 
                        $"(&(objectCategory={objectCategory})(objectClass={objectClass})(member={distinguishedName}))";
                        
                    var result = PagingHandler(string.IsNullOrWhiteSpace(searchBase) ? this._searchBase : searchBase, 
                        getGroupsFilter, SearchScope.Subtree, _attributes);
                        
                    foreach (SearchResultEntry resultEntry in result)
                    {
                        if (typeof(T) == typeof(LdapEntry) && resultEntry.Attributes.Contains("objectClass"))
                        {
                            var objectClasses = resultEntry.Attributes["objectClass"];
                            bool isGroup = false;
                            isGroup = ContainsValueInAttribute(objectClasses, "group");
                            if (!isGroup)
                            {
                                foreach (string val in objectClasses.GetValues(typeof(string)))
                                {
                                    if (string.Equals(val, "group", StringComparison.OrdinalIgnoreCase))
                                    {
                                        isGroup = true;
                                        break;
                                    }
                                }
                            }
                            
                            if (isGroup)
                            {
                                entries.Add((T)(object)this.CreateEntryFromAttributes(resultEntry.DistinguishedName, resultEntry.Attributes));
                            }
                        }
                        else if (typeof(T) == typeof(LdapUser) && resultEntry.Attributes.Contains("objectClass"))
                        {
                            var objectClasses = resultEntry.Attributes["objectClass"];
                            bool isUser = false;                            
                            isUser = ContainsValueInAttribute(objectClasses, "user");                            
                            if (!isUser)
                            {
                                foreach (string val in objectClasses.GetValues(typeof(string)))
                                {
                                    if (string.Equals(val, "user", StringComparison.OrdinalIgnoreCase))
                                    {
                                        isUser = true;
                                        break;
                                    }
                                }
                            }
                            
                            if (isUser)
                            {
                                entries.Add((T)(object)this.CreateUserFromAttributes(resultEntry.DistinguishedName, resultEntry.Attributes));
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
            if (string.IsNullOrEmpty(distinguishedName))
            {
                return new Collection<ILdapEntry>();
            }

            var allEntries = new Collection<ILdapEntry>();
            
            using (var ldapConnection = this.GetConnection())
            {
                try
                {
                    var tokenGroupsFilter = "(objectClass=*)";
                    var tokenGroupsResult = PagingHandler(distinguishedName, tokenGroupsFilter, SearchScope.Base, new[] { "tokenGroups", "objectClass" });

                    foreach (SearchResultEntry entry in tokenGroupsResult)
                    {
                        var tokenGroups = entry.Attributes["tokenGroups"];
                        if (tokenGroups != null)
                        {
                            var sidFilters = new List<string>();
                            foreach (byte[] sidBytes in tokenGroups)
                            {
                                var sid = new SecurityIdentifier(sidBytes, 0).ToString();
                                sidFilters.Add($"(objectSid={sid})");
                            }

                            if (sidFilters.Count > 0)
                            {
                                var classFilter = objectClass == "*" ? "(|(objectClass=group)(objectClass=user))" 
                                    : $"(objectClass={objectClass})";
                                var categoryFilter = objectCategory == "*" ? "" 
                                    : $"(objectCategory={objectCategory})";
                                
                                var filter = $"(&{classFilter}{categoryFilter}(|{string.Join("", sidFilters)}))";
                                var result = PagingHandler(string.IsNullOrWhiteSpace(searchBase) ? this._searchBase : searchBase, 
                                    filter, SearchScope.Subtree, _attributes);

                                foreach (SearchResultEntry groupEntry in result)
                                {
                                    if (ContainsValueInAttribute(groupEntry.Attributes["objectClass"], "group"))
                                    {
                                        allEntries.Add(this.CreateEntryFromAttributes(groupEntry.DistinguishedName, groupEntry.Attributes));
                                    }
                                    else if (ContainsValueInAttribute(groupEntry.Attributes["objectClass"], "user"))
                                    {
                                        allEntries.Add(this.CreateUserFromAttributes(groupEntry.DistinguishedName, groupEntry.Attributes));
                                    }
                                }
                            }
                        }
                    }
                }
                catch (DirectoryOperationException ex)
                {
                    var effectiveObjectClass = objectClass == "*" ? "group" : objectClass;
                    var effectiveObjectCategory = objectCategory == "*" ? "group" : objectCategory;
                    
                    var getGroupsFilter = recursive ? 
                        $"(&(objectCategory={effectiveObjectCategory})(objectClass={effectiveObjectClass})(member:1.2.840.113556.1.4.1941:={distinguishedName}))" : 
                        $"(&(objectCategory={effectiveObjectCategory})(objectClass={effectiveObjectClass})(member={distinguishedName}))";
                        
                    var result = PagingHandler(string.IsNullOrWhiteSpace(searchBase) ? this._searchBase : searchBase, 
                        getGroupsFilter, SearchScope.Subtree, _attributes);
                        
                    foreach (SearchResultEntry groupEntry in result)
                    {
                        if (groupEntry.Attributes.Contains("objectClass"))
                        {
                            var objectClasses = groupEntry.Attributes["objectClass"];
                            bool isGroup = false;
                            bool isUser = false;
                            
                            if (effectiveObjectClass == "group")
                            {
                                isGroup = ContainsValueInAttribute(objectClasses, "group");
                                
                                if (!isGroup)
                                {
                                    foreach (string val in objectClasses.GetValues(typeof(string)))
                                    {
                                        if (string.Equals(val, "group", StringComparison.OrdinalIgnoreCase))
                                        {
                                            isGroup = true;
                                            break;
                                        }
                                    }
                                }
                                
                                if (isGroup)
                                {
                                    allEntries.Add(this.CreateEntryFromAttributes(groupEntry.DistinguishedName, groupEntry.Attributes));
                                    continue;
                                }
                            }
                            
                            if (effectiveObjectClass == "user")
                            {
                                isUser = ContainsValueInAttribute(objectClasses, "user");
                                                                if (!isUser)
                                {
                                    foreach (string val in objectClasses.GetValues(typeof(string)))
                                    {
                                        if (string.Equals(val, "user", StringComparison.OrdinalIgnoreCase))
                                        {
                                            isUser = true;
                                            break;
                                        }
                                    }
                                }
                                
                                if (isUser)
                                {
                                    allEntries.Add(this.CreateUserFromAttributes(groupEntry.DistinguishedName, groupEntry.Attributes));
                                }
                            }
                        }
                    }
                }
            }

            return allEntries;
        }

        /// <summary>
        /// Checks if a DirectoryAttribute contains a specific string value
        /// </summary>
        /// <param name="attribute">The directory attribute to check</param>
        /// <param name="value">The string value to look for</param>
        /// <returns>True if the value is found, false otherwise</returns>
        private bool ContainsValueInAttribute(DirectoryAttribute attribute, string value)
        {
            if (attribute == null || string.IsNullOrEmpty(value))
            {
                return false;
            }
            try
            {
                string[] values = attribute.GetValues(typeof(string)) as string[];
                if (values != null)
                {
                    foreach (string val in values)
                    {
                        if (val.Equals(value, StringComparison.OrdinalIgnoreCase))
                        {
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error getting string values: {ex.Message}");
            }
            
            foreach (object attrValue in attribute)
            {
                string stringValue = attrValue as string;                
                if (stringValue != null && stringValue.Equals(value, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            
            return false;
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