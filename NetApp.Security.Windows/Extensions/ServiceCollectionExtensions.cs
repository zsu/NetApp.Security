using Microsoft.Extensions.DependencyInjection;
using System;

namespace NetApp.Security.Windows
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddLdapService(this IServiceCollection services, Action<LdapSettings> setupAction)
        {
            services.AddOptions<LdapSettings>().Configure(setupAction);
            services.AddTransient<NetApp.Security.ILdapService, LdapService>();
            services.AddTransient<ILdapService, LdapService>();
            return services;
        }
    }
}
