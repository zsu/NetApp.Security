using System;
using System.Collections.Generic;
using System.IO;

namespace NetApp.Security.Windows
{
    public interface ILdapService: NetApp.Security.ILdapService
    {

        void UpdatePhoto(string username, Stream stream);
    }
}