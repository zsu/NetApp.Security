[![NuGet](https://img.shields.io/nuget/v/NetApp.Security.svg)](https://www.nuget.org/packages/NetApp.Security)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

# What is NetApp.Security

Ldap library for .Net

# NuGet
```xml
Install-Package NetApp.Security.Windows (Contains additional functions targeting windows platform)
or
Install-Package NetApp.Security
```
# Getting started with NetApp.Security

  * Call the followings in Startup:  
  ```xml
     services.AddEncryptionService(options => {
           options.Key=Configuration.GetValue<string>("Encryption:Key");
           options.Iv = Configuration.GetValue<string>("Encryption:Iv");
       });
       services.AddLdapService(options => {
           Configuration.GetSection("Ldap").Bind(options);
       });
  ```
  * appsettings.json:  
  ```xml
    //AES Key and Iv
    "Encryption": {
      "Key": "xxxx",
      "Iv": "xx"
    },
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
