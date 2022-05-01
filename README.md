[![NuGet](https://img.shields.io/nuget/v/NetApp.Security.svg)](https://www.nuget.org/packages/NetApp.Security)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

# What is NetApp.Security

Ldap library for .Net

# NuGet
```xml
Install-Package NetApp.Security
```
# Getting started with NetApp.Security

  * Call the followings in Startup:  
  ```xml
            services.AddTransient<ILdapService, LdapService>();
            services.Configure<LdapSettings>(Configuration.GetSection("Ldap"));
  ```
  * appsettings.json:  
  ```xml
    "Ldap": {
      "ServerName": "xxx",
      "ServerPort": 636,
      "UseSSL": true,
      "Credentials": {
        "DomainUserName": "xxx@local",
        "Password": "xxx"
      },
      "SearchBase": "DC=xx,DC=xxx",
      "ContainerName": "DC=xx,DC=xxx",
      "DomainName": "xx.xxx",
      "DomainDistinguishedName": "DC=xx,DC=xxx"
    }
  ```
# License
All source code is licensed under MIT license - http://www.opensource.org/licenses/mit-license.php
