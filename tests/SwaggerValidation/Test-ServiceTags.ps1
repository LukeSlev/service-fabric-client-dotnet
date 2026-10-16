param(
    [Parameter(Mandatory = $true)]
    [string] $ModulePath
)

$ErrorActionPreference = 'Stop'
$moduleFile = Get-Item -LiteralPath $ModulePath
$directory = $moduleFile.DirectoryName
$references = @(
    (Join-Path $directory 'Microsoft.ServiceFabric.Common.dll'),
    (Join-Path $directory 'Microsoft.ServiceFabric.Client.dll'),
    (Join-Path $directory 'Microsoft.ServiceFabric.Client.Http.dll'),
    'System.Net.Http'
)
foreach ($reference in $references[0..2]) {
    Add-Type -Path $reference
}
Add-Type -ReferencedAssemblies $references -TypeDefinition @'
using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.ServiceFabric.Client;
using Microsoft.ServiceFabric.Client.Http;

public sealed class ServiceTagsCaptureHandler : DelegatingHandler
{
    public string Body { get; private set; }

    public IServiceFabricClient CreateClient()
    {
        return new ServiceFabricClientBuilder()
            .UseEndpoints(new Uri("http://localhost:19080"))
            .ConfigureHttpClientSettings(new HttpClientHandler(), this)
            .BuildAsync().GetAwaiter().GetResult();
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        this.Body = await request.Content.ReadAsStringAsync();
        return new HttpResponseMessage(HttpStatusCode.OK);
    }
}
'@

Import-Module -Name $moduleFile.FullName
$previousConnection = Get-Variable SFHttpClusterConnection -Scope Global -ErrorAction SilentlyContinue
$handler = New-Object ServiceTagsCaptureHandler
$client = $handler.CreateClient()
Set-Variable SFHttpClusterConnection -Value $client -Scope Global
$passed = 0
try {
    foreach ($kind in @('Stateful', 'Stateless')) {
        foreach ($operation in @('New', 'Update')) {
            foreach ($mode in @('populated', 'omitted', 'empty')) {
                $parameters = @{ $kind = $true }
                if ($operation -eq 'New') {
                    $parameters.Singleton = $true
                    $parameters.ApplicationId = 'app'
                    $parameters.ServiceName = 'fabric:/app/service'
                    $parameters.ServiceTypeName = 'TestType'
                    if ($kind -eq 'Stateful') {
                        $parameters.TargetReplicaSetSize = 3
                        $parameters.MinReplicaSetSize = 2
                        $parameters.HasPersistedState = $true
                    } else {
                        $parameters.InstanceCount = 1
                    }
                } else {
                    $parameters.ServiceId = 'app~service'
                    $parameters.Flags = '137363456'
                }
                if ($mode -eq 'populated') {
                    $parameters.TagsRequiredToPlace = [string[]]@('place')
                    $parameters.TagsRequiredToRun = [string[]]@('run')
                    $parameters.Tags = [string[]]@('notify')
                } elseif ($mode -eq 'empty') {
                    $parameters.Tags = [string[]]@()
                }

                & "$operation-SFService" @parameters
                $body = $handler.Body | ConvertFrom-Json
                if ($mode -eq 'populated') {
                    if ($body.ServiceTags.TagsRequiredToPlace[0] -ne 'place' -or
                        $body.ServiceTags.TagsRequiredToRun[0] -ne 'run' -or
                        $body.ServiceTags.ServiceTags[0] -ne 'notify') {
                        throw "$operation/$kind did not serialize all three tag collections."
                    }
                } elseif ($mode -eq 'omitted') {
                    if ($body.PSObject.Properties.Name -contains 'ServiceTags') {
                        throw "$operation/$kind emitted unspecified tags."
                    }
                } elseif ($null -eq $body.ServiceTags.ServiceTags -or $body.ServiceTags.ServiceTags.Count -ne 0) {
                    throw "$operation/$kind did not preserve an explicitly empty tag collection."
                }
                $passed++
                Write-Output "PASS: $operation/$kind/$mode"
            }
        }
    }
} finally {
    ([IDisposable]$client).Dispose()
    if ($previousConnection) {
        Set-Variable SFHttpClusterConnection -Value $previousConnection.Value -Scope Global
    } else {
        Remove-Variable SFHttpClusterConnection -Scope Global
    }
}
Write-Output "$passed service-tag checks passed."
