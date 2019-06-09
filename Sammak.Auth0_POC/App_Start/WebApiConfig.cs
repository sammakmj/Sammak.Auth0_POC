using Sammak.Auth0_POC.Helpers;
using Castle.Windsor;
using System.Web.Http;
using System.Web.Http.ExceptionHandling;

namespace Sammak.Auth0_POC.App_Start
{
    public static class WebApiConfig
    {
        public static IWindsorContainer Container { get; set; }

        public static void Register(HttpConfiguration config)
        {
            config.EnableCors();
            config.MapHttpAttributeRoutes();

            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );

            config.Services.Replace(typeof(IExceptionHandler), new GlobalExceptionHandler());
            //config.Services.Replace(typeof(IExceptionLogger), new UnhandledExceptionLogger());

            //var path = System.Web.Hosting.HostingEnvironment.ApplicationPhysicalPath + ConfigurationManager.AppSettings["DependenciesXml"];
            //Container = DependencyManagementService.Register(path);

            //Container.Register(Classes.FromThisAssembly()
            //    .BasedOn<IHttpController>()
            //    .LifestylePerWebRequest());

            //config.DependencyResolver = new WindsorMvcResolver(Container);

            config.Services.Replace(typeof(IExceptionHandler), new GlobalExceptionHandler());
            //config.Services.Replace(typeof(IExceptionLogger), new UnhandledExceptionLogger(Container.Resolve<ILogger>()));
        }
    }
}