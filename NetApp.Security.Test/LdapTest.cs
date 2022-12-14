using Microsoft.Extensions.Configuration;

namespace NetApp.Security.Test
{
    [TestClass]
    public class LdapTest
    {
        private IConfiguration _configuration;
        private ILdapService _ldapService;
        private LdapSettings _ldapSettings;
        private string _username = "dev1test";
        //private Mock<ILdapService> _ldapServiceMock;
        public LdapTest()
        {
        }
        [TestInitialize]
        public void Setup()
        {
            _ldapSettings = new LdapSettings();
            _ldapService = new LdapService(_ldapSettings);
            //_ldapServiceMock = new Mock<ILdapService>();
            //_ldapServiceMock.Setup(x => x.AddUser(null, null));
            //_ldapServiceMock.Setup(x => x.AddToGroups(null, null));
            //_ldapServiceMock.Setup(x => x.Delete(It.IsAny<string>(), It.IsAny<LdapPrincipalType>()));
            //_ldapServiceMock.Setup(x => x.RemoveFromGroups(null, null));
            //_ldapServiceMock.Setup(x => x.SetUserAttributes(null, null));
            //_ldapServiceMock.Setup(x => x.Authenticate(It.IsAny<string>(), It.IsAny<string>())).Returns((string a, string b) => _ldapService.Authenticate(a, b));
            //_ldapServiceMock.Setup(x => x.GetUsersInGroup(It.IsAny<string>(), It.IsAny<string>())).Returns((string a, string b) => _ldapService.GetUsersInGroup(a, b));
            //_ldapServiceMock.Setup(x => x.GetUsersInGroups(It.IsAny<ICollection<LdapEntry>>(), It.IsAny<string>())).Returns((ICollection<LdapEntry> a, string b) => _ldapService.GetUsersInGroups(a, b));
            //_ldapServiceMock.Setup(x => x.GetUserGroups(It.IsAny<string>(), It.IsAny<bool>())).Returns((string a, bool b) => _ldapService.GetUserGroups(a, b));
            //_ldapServiceMock.Setup(x => x.IsUserInGroup(It.IsAny<string>(), It.IsAny<List<string>>(), It.IsAny<bool>())).Returns((string a, List<string> b, bool c) => _ldapService.IsUserInGroup(a, b, c));
            //_ldapServiceMock.Setup(x => x.GetUserByLogonName(It.IsAny<string>())).Returns((string a) => _ldapService.GetUserByLogonName(a));
            //_ldapServiceMock.Setup(x => x.GetUsersByEmailAddress(It.IsAny<string>())).Returns((string a) => _ldapService.GetUsersByEmailAddress(a));
            //_ldapServiceMock.Setup(x => x.GetSubordinates(It.IsAny<string>())).Returns((string a) => _ldapService.GetSubordinates(a));
            //_ldapServiceMock.Setup(x => x.GetUserAttribute(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>())).Returns((string a, string b, string c) => _ldapService.GetUserAttribute(a, b, c));
        }

        [TestMethod]
        public void DeleteAndCreateUser()
        {
<<<<<<< HEAD
            string ou = $"OU=ou1,{_ldapSettings.DomainDistinguishedName}";
=======
            string ou = $"OU=ou1,{_ldapSettings.DomainDistinguishedName}";
            _ldapService.Delete(_username);
            Assert.IsNull(_ldapService.GetUserByLogonName(_username));
>>>>>>> 7f556c9 (Refactor)
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
            Assert.IsFalse(_ldapService.Authenticate(_username, "wrongpw"));
            Assert.IsTrue(_ldapService.Authenticate(_username, password));
        }
        [TestMethod]
        public void ChangeOU()
        {
            var user = _ldapService.GetUserByLogonName(_username);
            string oldOU = $"OU=ou1,{_ldapSettings.DomainDistinguishedName}";
            string oldParentOU = "ou1";
            string newParentOU = "newou";
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
<<<<<<< HEAD
            var group = new List<string> { "group1" };
=======
            var group = new List<string> { "group1", "group2" };
>>>>>>> 7f556c9 (Refactor)
            _ldapService.RemoveFromGroups(_username, group);
            _ldapService.AddToGroups(_username, group);
            Assert.IsTrue(_ldapService.IsUserInGroup(_username, group));
            _ldapService.RemoveFromGroups(_username, group);
        }
        [TestMethod]
        public void RemoveFromGroup()
        {
<<<<<<< HEAD
            var group = new List<string> { "group1" };
=======
            var group = new List<string> { "group1", "group2" };
>>>>>>> 7f556c9 (Refactor)
            _ldapService.AddToGroups(_username, group);
            _ldapService.RemoveFromGroups(_username, group);
            Assert.IsFalse(_ldapService.IsUserInGroup(_username, group));
        }
        [TestMethod]
        public void SetUserAttribute()
        {
            var attributes = new List<KeyValuePair<string, string>> { new KeyValuePair<string, string>("mobile", "111-111-1111"), new KeyValuePair<string, string>("division", "test") };
            var oldAttributes = new List<KeyValuePair<string, string>> { new KeyValuePair<string, string>("mobile", null), new KeyValuePair<string, string>("division", null) };
            _ldapService.SetUserAttributes(_username, attributes);
            Assert.IsTrue(_ldapService.GetUserAttribute(_username, "mobile") == "111-111-1111");
            Assert.IsTrue(_ldapService.GetUserAttribute(_username, "division") == "test");
            _ldapService.SetUserAttributes(_username, oldAttributes);
            Assert.IsTrue(_ldapService.GetUserAttribute(_username, "mobile") == null);
            Assert.IsTrue(_ldapService.GetUserAttribute(_username, "division") == null);
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
            var user = _ldapService.GetUserByLogonName(_username);
            var flag = Convert.ToInt32(user.AccountFlag);
            Assert.IsTrue((flag & 0x800000) != 0);
        }
        [TestMethod]
        public void SetPasswordNeverExpired()
        {
            _ldapService.SetPasswordNeverExpires(_username, true);
            var user = _ldapService.GetUserByLogonName(_username);
            var flag = Convert.ToInt32(user.AccountFlag);
            Assert.IsTrue((flag & 0x10000) != 0);
            _ldapService.SetPasswordNeverExpires(_username, false);
        }
        [TestMethod]
        public void SetManager()
        {
            string managername = "dev2test";
            string ou = $"OU=ou1,{_ldapSettings.DomainDistinguishedName}";
            _ldapService.Delete(managername);
            Assert.IsNull(_ldapService.GetUserByLogonName(managername));
            var item = new LdapUser();
            item.FirstName = "Dev2";
            item.LastName = "Test";
            item.UserName = managername;
            item.Password = "random1$";
            _ldapService.AddUser(item, ou);

            _ldapService.SetManager(_username, managername);
            var user = _ldapService.GetUserByLogonName(_username);
            var manager = _ldapService.GetUserByLogonName(managername);
            Assert.IsTrue(user.Manager == manager.DistinguishedName);
            _ldapService.Delete(managername);
        }
    }
}