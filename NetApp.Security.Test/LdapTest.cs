using Microsoft.Extensions.Configuration;
using NetApp.Common;

namespace NetApp.Security.Test
{
    [TestClass]
    public class LdapTest
    {
        private IConfiguration _configuration;
        private ILdapService _ldapService;
        private LdapSettings _ldapSettings;
        private IEncryptionService _encryptionService;
        private string _username = "dev1test";
        private string _ou = "ou1";
        private string _newou = "newou";
        private string _group1 = "group1";
        private string _group2 = "group2";
        //private Mock<ILdapService> _ldapServiceMock;
        public LdapTest()
        {
        }
        [TestInitialize]
        public void Setup()
        {
            _ldapSettings = new LdapSettings();
            _ldapService = new LdapService(_ldapSettings);
            ////_encryptionService = new EncryptionService();
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