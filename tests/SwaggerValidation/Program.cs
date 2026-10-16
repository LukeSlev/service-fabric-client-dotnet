// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace SwaggerValidation
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Reflection;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.ServiceFabric.Client;
    using Microsoft.ServiceFabric.Client.Http;
    using Microsoft.ServiceFabric.Common;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;

    internal static class Program
    {
        private const string References = @"[
            {""ParameterName"":""SecretA"",""ApplicationIdentityReference"":""IdentityA""},
            {""ParameterName"":""SecretB"",""ApplicationIdentityReference"":""IdentityB""}]";
        private static int passed;
        private static int failed;

        private static int Main()
        {
            Run("Application type listing reads the runtime property name", () =>
            {
                var item = ReadApplicationType(@"{""Name"":""AppType"",""Version"":""1.0"",
                    ""ManagedKeyVaultReferenceParameterList"":" + References + "}");
                Assert(item.Name == "AppType" && item.Version == "1.0", "Application identity changed.");
                AssertReferences(item);
            });
            Run("Listing by name reads references and preserves default parameters", () =>
            {
                var item = ReadApplicationType(@"{""Name"":""AppType"",
                    ""DefaultParameterList"":[{""Key"":""Setting"",""Value"":""configuration-value""}],
                    ""ManagedKeyVaultReferenceParameterList"":" + References + "}", byName: true);
                AssertReferences(item);
                Assert(item.DefaultParameterList["Setting"] == "configuration-value", "Default parameter changed.");
            });
            Run("Missing optional references remain null", () =>
                Assert(ReadApplicationType(@"{""Name"":""AppType""}").ManagedKeyVaultReferenceParameterList == null,
                    "Missing optional list should be null."));
            Run("Null references remain null", () =>
                Assert(ReadApplicationType(@"{""ManagedKeyVaultReferenceParameterList"":null}")
                    .ManagedKeyVaultReferenceParameterList == null, "Null list should remain null."));
            Run("Empty references remain empty", () =>
                Assert(!ReadApplicationType(@"{""ManagedKeyVaultReferenceParameterList"":[]}")
                    .ManagedKeyVaultReferenceParameterList.Any(), "Empty list should remain empty."));
            Run("Property matching stays case-insensitive and skips unknown fields", () =>
                AssertReferences(ReadApplicationType(@"{""Unknown"":{""Nested"":[1,2]},
                    ""managedkeyvaultreferenceparameterlist"":" + References + "}")));
            Run("Serialization writes only the runtime property name and round-trips", () =>
            {
                var item = new ApplicationTypeInfo(
                    managedKeyVaultReferenceParameterList: new[]
                    {
                        new ManagedKeyVaultReferenceParameter("SecretA", "IdentityA"),
                        new ManagedKeyVaultReferenceParameter("SecretB", "IdentityB"),
                    });
                var json = Serialize(item);
                Assert(json["ManagedKeyVaultReferenceParameters"] == null, "Obsolete wire name was emitted.");
                Assert(JToken.DeepEquals(json["ManagedKeyVaultReferenceParameterList"], JArray.Parse(References)),
                    "Serialized references differ from runtime shape.");
                AssertReferences(ReadApplicationType(json.ToString()));
            });
            Run("Serialization omits absent references", () =>
                Assert(Serialize(new ApplicationTypeInfo())["ManagedKeyVaultReferenceParameterList"] == null,
                    "Absent optional references were emitted."));

            Console.WriteLine("{0} passed, {1} failed.", passed, failed);
            return failed == 0 ? 0 : 1;
        }

        private static ApplicationTypeInfo ReadApplicationType(string itemJson, bool byName = false)
        {
            using (var handler = new ResponseHandler(
                @"{""ContinuationToken"":""next-page"",""Items"":[" + itemJson + "]}"))
            using (var inner = new HttpClientHandler())
            {
                var client = new ServiceFabricClientBuilder()
                    .UseEndpoints(new Uri("http://localhost:19080"))
                    .ConfigureHttpClientSettings(inner, handler)
                    .BuildAsync().GetAwaiter().GetResult();
                using ((IDisposable)client)
                {
                    var page = (byName
                        ? client.ApplicationTypes.GetApplicationTypeInfoListByNameAsync("AppType")
                        : client.ApplicationTypes.GetApplicationTypeInfoListAsync()).GetAwaiter().GetResult();
                    Assert(page.ContinuationToken.ToString() == "next-page", "Continuation token changed.");
                    Assert(handler.RequestPath == (byName ? "/ApplicationTypes/AppType" : "/ApplicationTypes"),
                        "Unexpected HTTP request path.");
                    return page.Data.Single();
                }
            }
        }

        private static JObject Serialize(ApplicationTypeInfo item)
        {
            var converter = typeof(ServiceFabricHttpClient).Assembly.GetType(
                "Microsoft.ServiceFabric.Client.Http.Serialization.ApplicationTypeInfoConverter", throwOnError: true);
            var serialize = converter.GetMethod("Serialize", BindingFlags.NonPublic | BindingFlags.Static);
            using (var text = new StringWriter())
            using (var writer = new JsonTextWriter(text))
            {
                serialize.Invoke(null, new object[] { writer, item });
                writer.Flush();
                return JObject.Parse(text.ToString());
            }
        }

        private static void AssertReferences(ApplicationTypeInfo item)
        {
            Assert(item.ManagedKeyVaultReferenceParameterList != null, "Runtime references were silently dropped.");
            var references = item.ManagedKeyVaultReferenceParameterList.ToArray();
            Assert(references.Length == 2, "Expected two references.");
            Assert(references[0].ParameterName == "SecretA" &&
                references[0].ApplicationIdentityReference == "IdentityA", "First reference changed.");
            Assert(references[1].ParameterName == "SecretB" &&
                references[1].ApplicationIdentityReference == "IdentityB", "Second reference changed.");
        }

        private static void Assert(bool condition, string message)
        {
            if (!condition)
            {
                throw new InvalidOperationException(message);
            }
        }

        private static void Run(string name, Action check)
        {
            try
            {
                check();
                passed++;
                Console.WriteLine("PASS: " + name);
            }
            catch (Exception exception)
            {
                failed++;
                Console.Error.WriteLine("FAIL: {0}\n{1}", name, exception);
            }
        }

        private sealed class ResponseHandler : DelegatingHandler
        {
            private readonly string json;

            internal ResponseHandler(string json)
            {
                this.json = json;
            }

            internal string RequestPath { get; private set; }

            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                Assert(request.Method == HttpMethod.Get, "Unexpected HTTP method.");
                this.RequestPath = request.RequestUri.AbsolutePath;
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(this.json),
                });
            }
        }
    }
}
