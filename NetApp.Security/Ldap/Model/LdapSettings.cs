namespace NetApp.Security
{
    public class LdapCredentials
    {
        public string DomainUserName { get; set; }

        public string Password { get; set; }
    }

    public class LdapSettings
    {
        public string ServerName { get; set; }

        public int ServerPort { get; set; }

        public bool UseSSL { get; set; }

        public string SearchBase { get; set; }

        public string ContainerName { get; set; }

        public string DomainName { get; set; }

        public string DomainDistinguishedName { get; set; }
        public int PageSize { get; set; } = 1000;
        public LdapCredentials Credentials { get; set; }
    }
}
