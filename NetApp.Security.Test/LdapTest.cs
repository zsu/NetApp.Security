using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using NetApp.Common;
using NetApp.Security.Windows;
using SkiaSharp;

namespace NetApp.Security.Test
{
    [TestClass]
    public class LdapTest
    {
        private IConfiguration _configuration;
        private ServiceProvider _serviceProvider;
        private ILdapService _ldapService;
        private NetApp.Security.Windows.ILdapService _windowsLdapService;
        private LdapSettings _ldapSettings;
        private IEncryptionService _encryptionService;
        private string _username = "devtest";
        private string _ou = "ou1";
        private string _newou = "newou";
        private string _group1 = "group1";
        private string _group2 = "group2";

        public LdapTest()
        {
        }

        [TestInitialize]
        public void Setup()
        {
            // Build configuration from appsettings.json and environment variables
            var builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddEnvironmentVariables(); // Support environment variable overrides
            
            _configuration = builder.Build();

            // Setup service collection
            var services = new ServiceCollection();
            
            // Register configuration
            services.AddSingleton<IConfiguration>(_configuration);
            
            // Get encryption key from configuration or environment variable
            var encryptionKey = _configuration.GetValue<string>("EncryptionKey:Key") 
                              ?? Environment.GetEnvironmentVariable("EncryptionKey__Key");
            
            if (!string.IsNullOrWhiteSpace(encryptionKey))
            {
            services.AddEncryptionService(encryptionKey);
            }
            
            // Configure LDAP settings
            services.Configure<LdapSettings>(options =>
            {
                _configuration.GetSection("Ldap").Bind(options);
            });
            
            // Register LDAP services
            services.AddLdapService(options =>
            {
                _configuration.GetSection("Ldap").Bind(options);
            });

            // Build service provider
            _serviceProvider = services.BuildServiceProvider();

            // Get services from container
            _encryptionService = _serviceProvider.GetRequiredService<IEncryptionService>();
            _ldapSettings = _serviceProvider.GetRequiredService<IOptions<LdapSettings>>().Value;
            
            // Initialize LDAP services with encryption service
            _ldapService = new NetApp.Security.LdapService(_ldapSettings, _encryptionService);
            _windowsLdapService = new NetApp.Security.Windows.LdapService(_ldapSettings, _encryptionService);
        }

        [TestCleanup]
        public void Cleanup()
        {
            _serviceProvider?.Dispose();
        }

        [TestMethod]
        public void UpdatePhoto()
        {
            // Ensure test user exists and is enabled for the test
            var user = _ldapService.GetUserByLogonName(_username);
            if (user == null)
            {
                // Create test user if it doesn't exist
                string ou = $"OU={_ou},{_ldapSettings.DomainDistinguishedName}";
                var newUser = new LdapUser
                {
                    FirstName = "Dev",
                    LastName = "Test",
                    UserName = _username,
                    Password = "random1$"
                };
                _ldapService.AddUser(newUser, ou);
            }

            // Create a test image using SkiaSharp
            using (var testImageStream = CreateTestImage(200, 200))
            {
                // Test 1: Upload photo for valid user
                testImageStream.Position = 0;
                try
                {
                    _windowsLdapService.UpdatePhoto(_username, testImageStream);

                    // Verify the photo was uploaded by checking user attributes
                    var jpegPhotoAttribute = _ldapService.GetUserAttribute(_username, LdapAttributes.JpegPhoto);
                    var thumbnailPhotoAttribute = _ldapService.GetUserAttribute(_username, LdapAttributes.ThumbnailPhoto);

                    // Both attributes should have values (note: binary data will be returned as base64 or similar)
                    Assert.IsNotNull(jpegPhotoAttribute, "jpegPhoto attribute should be set after upload");
                    Assert.IsNotNull(thumbnailPhotoAttribute, "thumbnailPhoto attribute should be set after upload");
                }
                catch (Exception ex)
                {
                    Assert.Fail($"UpdatePhoto failed for valid user: {ex.Message}");
                }
            }

            // Test 2: Upload smaller image (should not be resized)
            using (var smallImageStream = CreateTestImage(50, 50))
            {
                smallImageStream.Position = 0;
                try
                {
                    _windowsLdapService.UpdatePhoto(_username, smallImageStream);

                    // Should succeed without resizing
                    var jpegPhotoAttribute = _ldapService.GetUserAttribute(_username, LdapAttributes.JpegPhoto);
                    Assert.IsNotNull(jpegPhotoAttribute, "jpegPhoto should be updated for small image");
                }
                catch (Exception ex)
                {
                    Assert.Fail($"UpdatePhoto failed for small image: {ex.Message}");
                }
            }

            // Test 3: Test with null username (should throw ArgumentNullException)
            using (var testImageStream = CreateTestImage(100, 100))
            {
                Assert.ThrowsException<ArgumentNullException>(() =>
                {
                    _windowsLdapService.UpdatePhoto(null, testImageStream);
                }, "Should throw ArgumentNullException for null username");
            }

            // Test 4: Test with empty username (should throw ArgumentNullException)
            using (var testImageStream = CreateTestImage(100, 100))
            {
                Assert.ThrowsException<ArgumentNullException>(() =>
                {
                    _windowsLdapService.UpdatePhoto("", testImageStream);
                }, "Should throw ArgumentNullException for empty username");
            }

            // Test 5: Test with non-existent user (should throw Exception)
            using (var testImageStream = CreateTestImage(100, 100))
            {
                Assert.ThrowsException<Exception>(() =>
                {
                    _windowsLdapService.UpdatePhoto("nonexistentuser123", testImageStream);
                }, "Should throw Exception for non-existent user");
            }

            // Test 6: Test with invalid image stream (should throw ArgumentException)
            using (var invalidStream = new MemoryStream(new byte[] { 1, 2, 3, 4, 5 }))
            {
                Assert.ThrowsException<ArgumentException>(() =>
                {
                    _windowsLdapService.UpdatePhoto(_username, invalidStream);
                }, "Should throw ArgumentException for invalid image data");
            }
        }

        /// <summary>
        /// Creates a test image using SkiaSharp for testing purposes
        /// </summary>
        /// <param name="width">Image width</param>
        /// <param name="height">Image height</param>
        /// <returns>MemoryStream containing the test image</returns>
        private MemoryStream CreateTestImage(int width, int height)
        {
            var imageInfo = new SKImageInfo(width, height);
            using (var surface = SKSurface.Create(imageInfo))
            {
                var canvas = surface.Canvas;
                canvas.Clear(SKColors.White);

                // Draw a simple pattern for testing
                using (var paint = new SKPaint())
                {
                    paint.Color = SKColors.Blue;
                    paint.Style = SKPaintStyle.Fill;
                    canvas.DrawCircle(width / 2, height / 2, Math.Min(width, height) / 4, paint);

                    paint.Color = SKColors.Red;
                    canvas.DrawRect(10, 10, width - 20, height - 20, paint);
                }

                using (var image = surface.Snapshot())
                using (var data = image.Encode(SKEncodedImageFormat.Png, 100))
                {
                    var stream = new MemoryStream();
                    data.SaveTo(stream);
                    stream.Position = 0;
                    return stream;
                }
            }
        }

        [TestMethod]
        public void DeleteAndCreateUser()
        {
            string ou = $"OU={_ou},{_ldapSettings.DomainDistinguishedName}";
            _ldapService.Delete(_username);
            Assert.IsNull(_ldapService.GetUserByLogonName(_username));
            var item = new LdapUser();
            item.FirstName = "Dev1";
            item.LastName = "Test";
            item.UserName = _username;
            item.Password = "random1$";
            _ldapService.AddUser(item, ou);
            var user = _ldapService.GetUserByLogonName(_username);
            Assert.IsTrue(user != null);
            Assert.IsTrue(user.FirstName == item.FirstName);
            Assert.IsTrue(user.LastName == item.LastName);
            _ldapService.DisableAccount(_username, true);
        }

        [TestMethod]
        public void Authenticate()
        {
            string password = "random1$";
            _ldapService.DisableAccount(_username, false);
            Assert.IsFalse(_ldapService.Authenticate(_username, "wrongpw"));
            Assert.IsTrue(_ldapService.Authenticate(_username, password));
            _ldapService.DisableAccount(_username, true);
        }

        [TestMethod]
        public void ChangeOU()
        {
            var user = _ldapService.GetUserByLogonName(_username);
            string oldOU = $"OU={_ou},{_ldapSettings.DomainDistinguishedName}";
            string oldParentOU = _ou;
            string newParentOU = _newou;
            string newOU = $"OU={newParentOU},{oldOU}";
            _ldapService.ChangeOU(_username, newOU);
            Assert.IsTrue(_ldapService.GetParentOU(_username) == newParentOU);
            _ldapService.ChangeOU(_username, oldOU);
            Assert.IsTrue(_ldapService.GetParentOU(_username) == oldParentOU);
        }

        [TestMethod]
        public void GetAllUsers()
        {
            var result = _ldapService.GetAllUsers();
            Assert.IsTrue(result?.Count > 0);
        }

        [TestMethod]
        public void AddUserToGroup()
        {
            var group = new List<string> { _group1 };
            _ldapService.RemoveFromGroups(_username, group);
            _ldapService.AddToGroups(_username, group);
            Assert.IsTrue(_ldapService.IsUserInGroup(_username, group));
            _ldapService.RemoveFromGroups(_username, group);
        }

        [TestMethod]
        public void RemoveFromGroup()
        {
            var group = new List<string> { _group1 };
            _ldapService.AddToGroups(_username, group);
            _ldapService.RemoveFromGroups(_username, group);
            Assert.IsFalse(_ldapService.IsUserInGroup(_username, group));
        }

        [TestMethod]
        public void SetUserAttribute()
        {
            var attributes = new List<KeyValuePair<string, string>> { new KeyValuePair<string, string>(LdapAttributes.Mobile, "111-111-1111"), new KeyValuePair<string, string>(LdapAttributes.Division, "test") };
            var oldAttributes = new List<KeyValuePair<string, string>> { new KeyValuePair<string, string>(LdapAttributes.Mobile, null), new KeyValuePair<string, string>(LdapAttributes.Division, null) };
            _ldapService.SetUserAttributes(_username, attributes);
            Assert.IsTrue(_ldapService.GetUserAttribute(_username, LdapAttributes.Mobile) == "111-111-1111");
            Assert.IsTrue(_ldapService.GetUserAttribute(_username, LdapAttributes.Division) == "test");
            _ldapService.SetUserAttributes(_username, oldAttributes);
            Assert.IsTrue(_ldapService.GetUserAttribute(_username, LdapAttributes.Mobile) == null);
            Assert.IsTrue(_ldapService.GetUserAttribute(_username, LdapAttributes.Division) == null);
            _ldapService.SetUserAttributes(_username, oldAttributes);
        }

        [TestMethod]
        public void DisableAccount()
        {
            _ldapService.DisableAccount(_username, false);
            var user = _ldapService.GetUserByLogonName(_username);
            Assert.IsTrue(!user?.Disabled);
            _ldapService.DisableAccount(_username, true);
            user = _ldapService.GetUserByLogonName(_username);
            Assert.IsTrue(user?.Disabled);
        }

        [TestMethod]
        public void SetPasswordExpired()
        {
            _ldapService.SetPasswordExpired(_username, true);
            Assert.IsTrue(_ldapService.GetUserAttribute(_username, LdapAttributes.PwdLastSet) == "0");
            _ldapService.SetPasswordExpired(_username, false);
            Assert.IsTrue(_ldapService.GetUserAttribute(_username, LdapAttributes.PwdLastSet) != "0");
        }

        [TestMethod]
        public void SetPasswordNeverExpired()
        {
            _ldapService.SetPasswordNeverExpires(_username, true);
            var user = _ldapService.GetUserByLogonName(_username);
            var flag = Convert.ToInt32(user.AccountFlag);
            Assert.IsTrue((flag & 0x10000) == 0x10000);
            _ldapService.SetPasswordNeverExpires(_username, false);
        }

        [TestMethod]
        public void SetManager()
        {
            string managername = "dev2test";
            string ou = $"OU={_ou},{_ldapSettings.DomainDistinguishedName}";
            Assert.IsNull(_ldapService.GetUserByLogonName(managername));
            var item = new LdapUser();
            item.FirstName = "Dev2";
            item.LastName = "Test";
            item.UserName = managername;
            item.Password = "random1$";
            _ldapService.AddUser(item, ou);
            _ldapService.DisableAccount(managername, true);

            _ldapService.SetManager(_username, managername);
            var user = _ldapService.GetUserByLogonName(_username);
            var manager = _ldapService.GetUserByLogonName(managername);
            Assert.IsTrue(user.Manager == manager.DistinguishedName);
            _ldapService.Delete(managername);
        }

        [TestMethod]
        public void GetUserGroups()
        {
            var groupsRecursive1 = _ldapService.GetUserGroups(_username);
            var groups1 = _ldapService.GetUserGroups(_username, false);
            Assert.IsTrue(groups1?.Count > 0);
            Assert.IsTrue(groupsRecursive1?.Count>=groups1?.Count);
            var ldapService = new NetApp.Security.LdapService(_ldapSettings,_encryptionService);
            var groupsRecursive2 = ldapService.GetUserGroups(_username);
            var groups2 = ldapService.GetUserGroups(_username, false);
            Assert.IsTrue(groupsRecursive1?.Count == groupsRecursive2?.Count);
            Assert.IsTrue(groups1?.Count == groups2?.Count);
        }
    }
}