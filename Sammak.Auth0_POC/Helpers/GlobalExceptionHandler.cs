using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.ExceptionHandling;

namespace Sammak.Auth0_POC.Helpers
{
    public class GlobalExceptionHandler : ExceptionHandler
    {
        public override void Handle(ExceptionHandlerContext context)
        {
            var result = new HttpResponseMessage
            {
                Content = new StringContent(context.Exception.Message),
                ReasonPhrase = context.Exception.GetType().FullName
            };

            if (context.Exception.GetType() == typeof(ArgumentException) ||
                context.Exception.GetType() == typeof(InvalidOperationException))
            {
                result.StatusCode = HttpStatusCode.BadRequest;
            }
            else
            {
                result.StatusCode = HttpStatusCode.InternalServerError;
            }

            context.Result = new ErrorMessageResult(context.Request, result);
        }

        public class ErrorMessageResult : IHttpActionResult
        {
            private readonly HttpRequestMessage _request;
            private readonly HttpResponseMessage _httpResponseMessage;

            public ErrorMessageResult(HttpRequestMessage request, HttpResponseMessage httpResponseMessage)
            {
                _request = request;
                _httpResponseMessage = httpResponseMessage;
            }

            public Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
            {
                return Task.FromResult(_httpResponseMessage);
            }
        }
    }
}