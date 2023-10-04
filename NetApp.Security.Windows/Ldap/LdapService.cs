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
        protected override ICollection<T> GetChildren<T>(string searchBase, string? groupDistinguishedName = null, bool recursive = true)
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

        protected override ICollection<ILdapEntry> GetChildren(string searchBase, string? groupDistinguishedName = null,
        string objectCategory = "*", string objectClass = "*", bool recursive = true)
        {
            var allChildren = new HashSet<ILdapEntry>();

            var filter = string.IsNullOrEmpty(groupDistinguishedName)
            ? $"(&(objectCategory={objectCategory})(objectClass={objectClass}))"
            : (recursive ? $"(&(objectCategory={objectCategory})(objectClass={objectClass})(memberOf:1.2.840.113556.1.4.1941:={groupDistinguishedName}))" : $"(&(objectCategory={objectCategory})(objectClass={objectClass})(memberOf={groupDistinguishedName}))");

            using (var ldapConnection = this.GetConnection())
            {
                var result = PagingHandler(string.IsNullOrWhiteSpace(searchBase) ? this._searchBase : searchBase, filter, SearchScope.Subtree, _attributes);
                foreach (SearchResultEntry entry in result)
                {
                    if (objectClass == "group")
                    {
                        allChildren.Add(this.CreateEntryFromAttributes(entry.DistinguishedName, entry.Attributes));
                    }
                    if (objectClass == "user")
                        allChildren.Add(this.CreateUserFromAttributes(entry.DistinguishedName, entry.Attributes));
                }
            }
            return allChildren;
        }
        protected override ICollection<T> GetParent<T>(string searchBase, string? groupDistinguishedName = null, bool recursive = true)
        {
            var entries = new Collection<T>();

            var objectCategory = "*";
            var objectClass = "*";

            if (typeof(T) == typeof(LdapEntry))
            {
                objectClass = "group";
                objectCategory = "group";

                entries = this.GetParent(string.IsNullOrWhiteSpace(searchBase) ? this._searchBase : searchBase, groupDistinguishedName, objectCategory, objectClass, recursive)
                .Cast<T>().ToCollection();

            }

            if (typeof(T) == typeof(LdapUser))
            {
                objectCategory = "person";
                objectClass = "user";

                entries = this.GetParent(string.IsNullOrWhiteSpace(searchBase) ? this._searchBase : searchBase, groupDistinguishedName, objectCategory, objectClass, recursive).Cast<T>()
                .ToCollection();

            }

            return entries;
        }

        protected override ICollection<ILdapEntry> GetParent(string searchBase, string? groupDistinguishedName = null,
        string objectCategory = "*", string objectClass = "*", bool recursive = true)
        {
            if (!recursive)
                return base.GetParent(searchBase, groupDistinguishedName, objectCategory, objectClass, recursive);
            var allChildren = new HashSet<ILdapEntry>();

            var filter = string.IsNullOrEmpty(groupDistinguishedName)
            ? $"(&(objectCategory={objectCategory})(objectClass={objectClass}))"
            : (recursive ? $"(&(objectCategory={objectCategory})(objectClass={objectClass})(member:1.2.840.113556.1.4.1941:={groupDistinguishedName}))" : $"(&(objectCategory={objectCategory})(objectClass={objectClass})(member={groupDistinguishedName}))");

            using (var ldapConnection = this.GetConnection())
            {
                var result = PagingHandler(string.IsNullOrWhiteSpace(searchBase) ? this._searchBase : searchBase, filter, SearchScope.Subtree, _attributes);
                foreach (SearchResultEntry entry in result)
                {
                    if (objectClass == "group")
                    {
                        allChildren.Add(this.CreateEntryFromAttributes(entry.DistinguishedName, entry.Attributes));
                    }
                    if (objectClass == "user")
                        allChildren.Add(this.CreateUserFromAttributes(entry.DistinguishedName, entry.Attributes));
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