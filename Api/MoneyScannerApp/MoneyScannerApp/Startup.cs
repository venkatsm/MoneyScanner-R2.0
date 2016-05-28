using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(MoneyScannerApp.Startup))]
namespace MoneyScannerApp
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
