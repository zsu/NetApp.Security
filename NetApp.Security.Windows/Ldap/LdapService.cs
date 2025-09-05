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
using SkiaSharp;

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
            
            // Reset stream position to beginning
            stream.Position = 0;
            byte[] bytes;
            using (var ms = new MemoryStream())
            {
                stream.CopyTo(ms);
                bytes = ms.ToArray();
            }
            
            // Update jpegPhoto attribute
            var attribute = new DirectoryAttributeModification();
            attribute.Operation = DirectoryAttributeOperation.Replace;
            attribute.Name = "jpegPhoto";
            attribute.Add(bytes);
            var request = new ModifyRequest(user.DistinguishedName, attribute);
            using (var ldapConnection = this.GetConnection())
            {
                var response = ldapConnection.SendRequest(request);
            }

            // Process thumbnail
            stream.Position = 0;
            using (var codec = SKCodec.Create(stream))
            {
                if (codec == null)
                    throw new ArgumentException("Unable to decode image from stream", nameof(stream));

                var info = codec.Info;
                if (info.Width > size || info.Height > size)
                {
                    stream.Position = 0;
                    var resizedBytes = ResizeImageToBytes(stream, info, size);
                    
                    // Update thumbnailPhoto attribute
                    attribute = new DirectoryAttributeModification();
                    attribute.Operation = DirectoryAttributeOperation.Replace;
                    attribute.Name = "thumbnailPhoto";
                    attribute.Add(resizedBytes);
                    request = new ModifyRequest(user.DistinguishedName, attribute);
                    using (var ldapConnection = this.GetConnection())
                    {
                        var response = ldapConnection.SendRequest(request);
                    }
                }
                else
                {
                    // Image is already small enough, use original bytes for thumbnail
                    attribute = new DirectoryAttributeModification();
                    attribute.Operation = DirectoryAttributeOperation.Replace;
                    attribute.Name = "thumbnailPhoto";
                    attribute.Add(bytes);
                    request = new ModifyRequest(user.DistinguishedName, attribute);
                    using (var ldapConnection = this.GetConnection())
                    {
                        var response = ldapConnection.SendRequest(request);
                    }
                }
            }
        }

        protected override ICollection<T> GetChildren<T>(string searchBase, string groupDistinguishedName = null, bool recursive = true)
        {
            var entries = new Collection<T>();
            string objectCategory;
            string objectClass;

            if (typeof(T) == typeof(LdapEntry))
            {
                objectCategory = "group";
                objectClass = "group";
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

            var allChildren = GetChildren(searchBase, groupDistinguishedName, objectCategory, objectClass, recursive);

            foreach (var child in allChildren)
            {
                if (child is T typedChild)
                {
                    entries.Add(typedChild);
                }
            }

            return entries;
        }

        protected override ICollection<ILdapEntry> GetChildren(string searchBase, string groupDistinguishedName = null,
        string objectCategory = "*", string objectClass = "*", bool recursive = true)
        {
            var allChildren = new HashSet<ILdapEntry>();
            if (string.IsNullOrEmpty(groupDistinguishedName))
            {
                using (var ldapConnection = this.GetConnection())
                {
                    var classFilter = objectClass == "*" ? "(|(objectClass=group)(objectClass=user))" 
                          : $"(objectClass={objectClass})";
                    var categoryFilter = objectCategory == "*" ? "" 
                          : $"(objectCategory={objectCategory})";
                    
                    var allEntriesFilter = $"(&{classFilter}{categoryFilter})";
                    var result = PagingHandler(string.IsNullOrWhiteSpace(searchBase) ? this._searchBase : searchBase, 
                        allEntriesFilter, SearchScope.Subtree, _attributes);

                    foreach (SearchResultEntry entry in result)
                    {
                        if ((objectClass == "*" || objectClass == "group") && ContainsValueInAttribute(entry.Attributes["objectClass"], "group"))
                        {
                            allChildren.Add(this.CreateEntryFromAttributes(entry.DistinguishedName, entry.Attributes));
                        }
                        else if ((objectClass == "*" || objectClass == "user") && ContainsValueInAttribute(entry.Attributes["objectClass"], "user"))
                        {
                            allChildren.Add(this.CreateUserFromAttributes(entry.DistinguishedName, entry.Attributes));
                        }
                    }
                }
                return allChildren;
            }
            var membershipFilter = recursive
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
                    membershipFilter,
                    SearchScope.Subtree,
                    rangeAttributes.ToArray());

                foreach (SearchResultEntry entry in result)
                {
                    if ((objectClass == "*" || objectClass == "group") && ContainsValueInAttribute(entry.Attributes["objectClass"], "group"))
                    {
                        allChildren.Add(this.CreateEntryFromAttributes(entry.DistinguishedName, entry.Attributes));
                    }
                    else if ((objectClass == "*" || objectClass == "user") && ContainsValueInAttribute(entry.Attributes["objectClass"], "user"))
                    {
                        allChildren.Add(this.CreateUserFromAttributes(entry.DistinguishedName, entry.Attributes));
                    }
                }
            }

            return allChildren;
        }

		protected override ICollection<T> GetParent<T>(string searchBase, string distinguishedName = null, bool recursive = true)
		{
			var results = new Collection<T>();
			if (string.IsNullOrWhiteSpace(distinguishedName)) return results;

			string objectCategory;
			string objectClass;
			if (typeof(T) == typeof(LdapEntry))
			{
				objectCategory = "group";
				objectClass = "group";
			}
			else if (typeof(T) == typeof(LdapUser))
			{
				objectCategory = "group";
				objectClass = "group";
			}
			else
			{
				return results;
			}

			var filter = recursive
				? $"(&(objectCategory={objectCategory})(objectClass={objectClass})(member:1.2.840.113556.1.4.1941:={distinguishedName}))"
				: $"(&(objectCategory={objectCategory})(objectClass={objectClass})(member={distinguishedName}))";

			using (var ldapConnection = this.GetConnection())
			{
				var searchBaseToUse = string.IsNullOrWhiteSpace(searchBase) ? this._searchBase : searchBase;
				var searchResult = PagingHandler(searchBaseToUse, filter, SearchScope.Subtree, _attributes);
				foreach (SearchResultEntry entry in searchResult)
				{
					if (ContainsValueInAttribute(entry.Attributes["objectClass"], "group"))
					{
						if (typeof(T) == typeof(LdapEntry))
							results.Add((T)(object)this.CreateEntryFromAttributes(entry.DistinguishedName, entry.Attributes));
						else if (typeof(T) == typeof(LdapUser))
							results.Add((T)(object)this.CreateUserFromAttributes(entry.DistinguishedName, entry.Attributes));
					}
				}
			}
			return results;
		}

		protected override ICollection<ILdapEntry> GetParent(string searchBase, string distinguishedName = null,
			string objectCategory = "*", string objectClass = "*", bool recursive = true)
		{
			var all = new Collection<ILdapEntry>();
			if (string.IsNullOrWhiteSpace(distinguishedName)) return all;
			var effectiveObjectClass = objectClass == "*" ? "group" : objectClass;
			var effectiveObjectCategory = objectCategory == "*" ? "group" : objectCategory;

			var filter = recursive
				? $"(&(objectCategory={effectiveObjectCategory})(objectClass={effectiveObjectClass})(member:1.2.840.113556.1.4.1941:={distinguishedName}))"
				: $"(&(objectCategory={effectiveObjectCategory})(objectClass={effectiveObjectClass})(member={distinguishedName}))";

			using (var ldapConnection = this.GetConnection())
			{
				var searchBaseToUse = string.IsNullOrWhiteSpace(searchBase) ? this._searchBase : searchBase;
				var result = PagingHandler(searchBaseToUse, filter, SearchScope.Subtree, _attributes);
				foreach (SearchResultEntry entry in result)
				{
					if (ContainsValueInAttribute(entry.Attributes["objectClass"], "group"))
					{
						all.Add(this.CreateEntryFromAttributes(entry.DistinguishedName, entry.Attributes));
					}
				}
			}
			return all;
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

        private byte[] ResizeImageToBytes(Stream imageStream, SKImageInfo originalInfo, int maxSize)
        {
            var (newWidth, newHeight) = CalculateNewDimensions(originalInfo.Width, originalInfo.Height, maxSize);
            imageStream.Position = 0;
            using (var originalBitmap = SKBitmap.Decode(imageStream))
            using (var resizedBitmap = originalBitmap.Resize(new SKImageInfo(newWidth, newHeight), SKFilterQuality.High))
            using (var image = SKImage.FromBitmap(resizedBitmap))
            using (var data = image.Encode(SKEncodedImageFormat.Jpeg, 90))
            {
                return data.ToArray();
            }
        }

        private (int width, int height) CalculateNewDimensions(int originalWidth, int originalHeight, int maxSize)
        {
            if (originalWidth <= maxSize && originalHeight <= maxSize)
                return (originalWidth, originalHeight);

            double ratio = Math.Min((double)maxSize / originalWidth, (double)maxSize / originalHeight);
            int newWidth = (int)(originalWidth * ratio);
            int newHeight = (int)(originalHeight * ratio);
            
            return (newWidth, newHeight);
        }
    }
}