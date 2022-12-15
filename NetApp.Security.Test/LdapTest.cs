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
        public void CreateUser()
        {
            string ou = $"OU=ou1,{_ldapSettings.DomainDistinguishedName}";
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
            var group = new List<string> { "group1" };
            _ldapService.RemoveFromGroups(_username, group);
            _ldapService.AddToGroups(_username, group);
            Assert.IsTrue(_ldapService.IsUserInGroup(_username, group));
            _ldapService.RemoveFromGroups(_username, group);
        }
        [TestMethod]
        public void RemoveFromGroup()
        {
            var group = new List<string> { "group1" };
            _ldapService.AddToGroups(_username, group);
            _ldapService.RemoveFromGroups(_username, group);
            Assert.IsFalse(_ldapService.IsUserInGroup(_username, group));
        }
        [TestMethod]
        public void DeleteUser()
        {
            _ldapService.Delete(_username);
            Assert.IsNull(_ldapService.GetUserByLogonName(_username));
        }
    }
}