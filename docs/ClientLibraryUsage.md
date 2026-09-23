## Microsoft.ServiceFabric.Client.Http

## Client Library nuget package version and Service Fabric Runtime Compatibility
### Stable releases
Nuget Package Version | Compatible Service Fabric Runtime version
-|-
4.7.* | >= 9.0
4.6.* | >= 8.2
4.5.* | >= 8.1
4.4.* | >= 8.0
4.2.* | >= 7.2
4.1.* | >= 7.1
4.0.* | >= 7.0
3.0.* | >= 6.5

### Preview releases
Nuget Package Version | Compatible Service Fabric Runtime version
-|-
3.0.0-preview* | >= 6.5
3.0.0-preview* | >= 6.5
2.0.0-preview* | >= 6.4
1.0.0-preview59 - 1.0.0-preview61 | >=6.3
1.0.0-preview58 | >=6.2


## Using the Client Library
### Connecting to unsecured cluster
```csharp
// create client
var sfClient = new ServiceFabricClientBuilder()
                .UseEndpoints(new Uri(@"http://<cluster_fqdn>:19080"))
                .BuildAsync().GetAwaiter().GetResult();
```

### Connecting to cluster secured with X509 certificate
Certificate information must be provided when connecting to a secured cluster from within the cluster or outside the cluster.
```csharp
// create client using ServiceFabricClientBuilder.UseX509Security
var sfClient = new ServiceFabricClientBuilder()
                .UseEndpoints(new Uri(@"http://<cluster_fqdn>:19080"))
                .UseX509Security(GetSecurityCredentials)
                .BuildAsync().GetAwaiter().GetResult();

Func<CancellationToken, Task<SecuritySettings>> GetSecurityCredentials = (ct) =>
{
    // get the X509Certificate2 either from Certificate store or from file.
    var clientCert = new System.Security.Cryptography.X509Certificates.X509Certificate2("<Path to .pfx file>", "password");
    var remoteSecuritySettings = new RemoteX509SecuritySettings(new List<string> { "server_cert_thumbprint" });
    return Task.FromResult<SecuritySettings>(new X509SecuritySettings(clientCert, remoteSecuritySettings));
};
```

#### Handling multiple issuer thumbprints
You can specify a comma delimited list as the issuerCertThumbprint for a RemoteX509SecuritySettings object to check against multiple issuers.

#### Per-cluster issuer trust during migration

By default, common-name/issuer validation requires a chain trusted by the service host.
`ignoreCrlOfflineError: true` alone does not allow an untrusted customer root.

For migration clients that must connect to a customer cluster using a private CA, explicitly
enable `allowUntrustedRootWithPinnedIssuer` on that client's remote security settings:

```csharp
var remoteSecuritySettings = new RemoteX509SecuritySettings(
    new List<X509Name>
    {
        new X509Name(expectedCustomerCertificateName, customerIssuerThumbprint),
    },
    ignoreCrlOfflineError: true,
    allowUntrustedRootWithPinnedIssuer: true);

var securitySettings = new X509SecuritySettings(clientCert, remoteSecuritySettings);
```

Pass these settings through the existing `UseX509Security` credentials callback. The same
remote settings also work with claims credentials. Only enable the option for the relevant
cluster/client; it does not modify any certificate store or process-wide TLS callback.
The migration caller must explicitly pass the third argument; existing binaries and
two-argument constructor calls retain their previous behavior.

With this option:

- The certificate must match a configured common name or DNS name and the **same entry's
  direct issuer or root CA certificate thumbprint**. Matching is exact and case-insensitive, as with
  existing name validation; the configured cluster identity may differ from the endpoint hostname.
- The chain is rebuilt for the actual peer certificate with server-authentication usage.
  The pinned certificate must be a CA in the built chain. The certificates needed to reach
  it must be available to the chain builder (typically supplied by the server or retrieved
  through AIA). A thumbprint is not sufficient to reconstruct a missing CA certificate.
- A matching issuer pin replaces only root trust: `UntrustedRoot`, or `PartialChain`
  above a verified pinned direct issuer, is allowed. For a root pin, the chain must reach
  that root, including validation of every intermediate link. The last certificate of an
  incomplete chain is not treated as a root. Arbitrary intermediate pins and the leaf's
  own thumbprint are not accepted.
- Invalid signatures, expired/not-yet-valid certificates, invalid CA constraints,
  wrong usages, unsupported critical extensions, revoked certificates, and other
  disallowed chain errors are rejected. Available certificates above the issuer are
  still validated; their errors are not ignored.
- The transport's revocation mode and scope are retained. `ignoreCrlOfflineError` allows
  offline CRL failures and their accompanying `RevocationStatusUnknown` flag, not
  standalone unknown-revocation errors or a revoked certificate. Keep it `false` if
  migration must also fail when revocation infrastructure is offline.
- Entries without an issuer pin still require a normally trusted chain. The opt-in checks
  configured names and pins even if TLS initially reports no policy errors.

Issuer pins must come from trusted cluster configuration, not from the unverified endpoint.
Existing constructors leave this option disabled; ordinary public-CA and thumbprint-based
clients are unchanged.

Root pinning supports customer configurations where the RP accepts the root rather than the
direct issuer thumbprint. This is not full RP-validator parity: self-signed leaf pins remain
unsupported, and the HTTP client retains its server-authentication and revocation policies.

#### Building and validating the .NET Framework fork

Build the Framework solution directly rather than using the repository build script:

```powershell
msbuild .\src\Microsoft.ServiceFabric.Client.Http.FX.sln /t:Build /p:Configuration=Debug
```

The fork currently targets .NET Framework 4.6.2. The changed production files are already
included in the FX projects; no generated-file includes or framework retargeting are needed.
Outputs are in `src\Microsoft.ServiceFabric.Client.Http\bin\Debug`.

The certificate regression executable requires .NET Framework 4.8 for in-memory certificate
generation and has no test-package dependencies. It references the actual FX projects and
does not install certificates in any store:

```powershell
msbuild .\tests\CertificateValidation\CertificateValidation.csproj /t:Build /p:Configuration=Debug
.\tests\CertificateValidation\bin\Debug\CertificateValidation.exe
# Optional integration check against a publicly trusted HTTPS endpoint (requires network access):
.\tests\CertificateValidation\bin\Debug\CertificateValidation.exe --public-tls
```

The tests cover direct issuer and root pins, partial chains above a pinned issuer, wrong names/pins,
signature and validity failures, CA/usage constraints, revocation error combinations,
default behavior, settings refresh, and the Framework HTTP handler's authentication callback.

### Connecting to cluster secured with Azure Active Directory
There are different ways to connect to the cluster secured with Azure Active Directory depending on if you have the AAD metadata(authority, resource, clientId) to get the token from Azure Active Directory. If you have the AAD metadata, use the option 1 below, if you don't have the AAD metadata, use the option 2 below.
#### 1. You have the AAD metadata to get the token from Azure Active Directory.
If you have the AAD metadata(authority, resource, client id) to get the token from Azure Active Directory, you can use it directly to get the token as shown below.
```csharp
// create client using ServiceFabricClientBuilder.UseAzureActiveDirectorySecurity
var sfClient = new ServiceFabricClientBuilder()
                .UseEndpoints(new Uri(@"http://<cluster_fqdn>:19080"))
                .UseAzureActiveDirectorySecurity(GetSecurityCredentials)
                .BuildAsync().GetAwaiter().GetResult();

Func<CancellationToken, Task<SecuritySettings>> GetSecurityCredentials = (ct) =>
{
    var token = GetAccessTokenAsync(ct).GetAwaiter().GetResult();    
    var remoteSecuritySettings = new RemoteX509SecuritySettings(new List<string> { "server_cert_thumbprint" });
    return Task.FromResult<SecuritySettings>(new AzureActiveDirectorySecuritySettings(token, remoteSecuritySettings));
};

public static async Task<string> GetAccessTokenAsync(CancellationToken cancellationToken)
{
    // get token from azure active directory using Active Directory APIs
    var authority = @"https://login.microsoftonline.com/" + "tenant_Id";
    var authContext = new AuthenticationContext(authority);
    var authResult = await authContext.AcquireTokenAsync("resource_Id", "client_Id", new UserCredential());
    return authResult.AccessToken;
}
```
#### 2. You don't have the AAD metadata to get the token from Azure Active Directory.
If you don't have the AAD metadata(authority, resource, client id) to get the token from Azure Active Directory, you can provide a delegate which will be invoked with AAD metadata fetched from the cluster. This approach is shown in the code below:

```csharp
// create client using ServiceFabricClientBuilder.UseAzureActiveDirectorySecurity
var sfClient = new ServiceFabricClientBuilder()
                .UseEndpoints(new Uri(@"http://<cluster_fqdn>:19080"))
                .UseAzureActiveDirectorySecurity(GetSecurityCredentials)
                .BuildAsync().GetAwaiter().GetResult();

Func<CancellationToken, Task<SecuritySettings>> GetSecurityCredentials = (ct) =>
{
    var remoteSecuritySettings = new RemoteX509SecuritySettings(new List<string> { "server_cert_thumbprint" });
    return Task.FromResult<SecuritySettings>(new AzureActiveDirectorySecuritySettings(GetAccessTokenAsync, remoteSecuritySettings));
};

public static async Task<string> GetAccessTokenAsync(AadMetadata aad, CancellationToken cancellationToken)
{
    // get token from azure active directory using Active Directory APIs
    var authContext = new AuthenticationContext(aad.Authority);
    var authResult = await authContext.AcquireTokenAsync(aad.Cluster, aad.Client, new UserCredential());
    return authResult.AccessToken;
}

```


APIs in this client library are categorized into following categories (available ```interface  IServiceFabricClient```) (can be accessed using the ```sfClient``` instance created with aboove code snippet):
* Applications
* ApplicationTypes
* BackupRestore
* ChaosClient
* CodePackages
* Cluster
* ComposeDeployments
* Faults
* ImageStore
* Infrastructure
* Partitions
* Nodes
* Replicas
* Properties
* Repairs
* Services
* ServicePackages
* ServiceTypes
* EventsStore

### Performing operations
Once you have connected to cluster as mentioned, you can perform various management operations as shown below:

```csharp
// get cluster manifest and health
var manifest = await sfClient.Cluster.GetClusterManifestAsync();
var health = await sfClient.Cluster.GetClusterHealthAsync();

// upload, provision and create application
await sfClient.Applications.UploadApplicationPackageAsync("Path_To_Application_Package", applicationPackagePathInImageStore:"TestApp");

await sfClient.ApplicationTypes.ProvisionApplicationTypeAsync(new ProvisionApplicationTypeDescription("TestApp"));

var appParams = new Dictionary<string, string>();
appParams.Add("Parameter1", "1");
var appDesc = new ApplicationDescription(new ApplicationName("fabric:/ApplicationFromLib"), "ApplicationType", "1.0.0", appParams);
await sfClient.Applications.CreateApplicationAsync(appDesc);

// get partition information
var partition = await sfClient.Partitions.GetPartitionInfoAsync(new Guid("8b8c58e6-f18a-477c-8b8d-87123f754b72"));

```
