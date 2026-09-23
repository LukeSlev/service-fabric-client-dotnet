// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace CertificateValidation
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net.Http;
    using System.Net.Security;
    using System.Reflection;
    using System.Security.Authentication;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using Microsoft.ServiceFabric.Client;
    using Microsoft.ServiceFabric.Common.Security;

    internal static class Program
    {
        private const string ServerName = "customer.example";
        private static int passed;
        private static int failed;

        private static int Main(string[] args)
        {
            using (var root = CreateCertificate("Root-" + Guid.NewGuid(), null, true))
            using (var issuer = CreateCertificate("Issuer-" + Guid.NewGuid(), root, true))
            using (var leaf = CreateCertificate(ServerName, issuer))
            using (var wrongIssuer = CreateCertificate("Other-" + Guid.NewGuid(), root, true))
            {
                var pinned = Settings(issuer.Thumbprint);
                var certificates = new[] { issuer, root };
                Run("Private root is not locally trusted", () =>
                {
                    using (var chain = BuildChain(leaf, certificates))
                    {
                        Expect(chain.ChainStatus.Any(s => (s.Status & X509ChainStatusFlags.UntrustedRoot) != 0), true);
                    }
                });
                Run("Reproduce legacy rejection despite matching name and issuer", () =>
                    Expect(Validate(leaf, certificates, Settings(issuer.Thumbprint, enabled: false)), false));
                Run("Legacy offline-CRL option does not allow an untrusted root", () =>
                    Expect(Validate(leaf, certificates, Settings(issuer.Thumbprint, enabled: false, ignoreOffline: true)), false));
                Run("Opt-in accepts matching name and direct issuer without installing a root", () =>
                    Expect(Validate(leaf, certificates, pinned), true));
                Run("Transport server-auth EKU is not duplicated during chain rebuild", () =>
                {
                    using (var chain = BuildChain(leaf, certificates))
                    {
                        chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
                        chain.Build(leaf);
                        Expect(new ServerCertificateValidator(pinned).ValidateCertificate(
                            null, leaf, chain, SslPolicyErrors.RemoteCertificateChainErrors), true);
                    }
                });
                Run("Opt-in accepts a directly pinned root CA", () =>
                {
                    using (var directLeaf = CreateCertificate(ServerName, root))
                    {
                        Expect(Validate(directLeaf, new[] { root }, Settings(root.Thumbprint)), true);
                    }
                });
                Run("Missing parent above pinned issuer does not require global root trust", () =>
                {
                    using (var partialRoot = CreateCertificate("PartialRoot-" + Guid.NewGuid(), null, true))
                    using (var partialIssuer = CreateCertificate("PartialIssuer-" + Guid.NewGuid(), partialRoot, true))
                    using (var partialLeaf = CreateCertificate(ServerName, partialIssuer))
                    using (var chain = BuildChain(partialLeaf, new[] { partialIssuer }))
                    {
                        Expect(chain.ChainStatus.Any(s => (s.Status & X509ChainStatusFlags.PartialChain) != 0), true);
                        Expect(new ServerCertificateValidator(Settings(partialIssuer.Thumbprint)).ValidateCertificate(
                            null, partialLeaf, chain, SslPolicyErrors.RemoteCertificateChainErrors), true);
                    }
                });
                Run("No issuer pin still requires normal trust", () =>
                    Expect(Validate(leaf, certificates, Settings(null)), false));
                Run("Empty issuer pin cannot authorize an untrusted CA", () =>
                    Expect(Validate(leaf, certificates, Settings(" , ")), false));
                Run("Wrong configured identity is rejected", () =>
                    Expect(Validate(leaf, certificates, Settings(issuer.Thumbprint, name: "other.example")), false));
                Run("Wrong issuer is rejected", () =>
                    Expect(Validate(leaf, certificates, Settings(wrongIssuer.Thumbprint)), false));
                Run("Root pin accepts a valid chain through an intermediate CA", () =>
                    Expect(Validate(leaf, certificates, Settings(root.Thumbprint)), true));
                Run("Root pin does not relax legacy validation without the opt-in", () =>
                    Expect(Validate(leaf, certificates, Settings(root.Thumbprint, enabled: false)), false));
                Run("Root pin still requires the configured identity", () =>
                    Expect(Validate(leaf, certificates, Settings(root.Thumbprint, name: "other.example")), false));
                Run("Root rollover list uses exact case-insensitive thumbprints", () =>
                {
                    Expect(Validate(leaf, certificates, Settings(wrongIssuer.Thumbprint + ", " + root.Thumbprint.ToLowerInvariant())), true);
                    Expect(Validate(leaf, certificates, Settings("00" + root.Thumbprint)), false);
                });
                Run("Unrelated root in the extra store cannot authorize the chain", () =>
                {
                    using (var unrelated = CreateCertificate("UnrelatedRoot-" + Guid.NewGuid(), null, true))
                    {
                        Expect(Validate(leaf, new[] { issuer, root, unrelated }, Settings(unrelated.Thumbprint)), false);
                    }
                });
                Run("Root pin supports multiple intermediate links but not arbitrary intermediate pins", () =>
                {
                    using (var subordinate = CreateCertificate("Subordinate-" + Guid.NewGuid(), issuer, true))
                    using (var deepLeaf = CreateCertificate(ServerName, subordinate))
                    {
                        var deepChain = new[] { subordinate, issuer, root };
                        Expect(Validate(deepLeaf, deepChain, Settings(root.Thumbprint)), true);
                        Expect(Validate(deepLeaf, deepChain, Settings(issuer.Thumbprint)), false);
                    }
                });
                Run("Root pin requires the root in the chain, not an incomplete-chain terminus", () =>
                {
                    using (var missingRoot = CreateCertificate("AbsentRoot-" + Guid.NewGuid(), null, true))
                    using (var upper = CreateCertificate("Upper-" + Guid.NewGuid(), missingRoot, true))
                    using (var direct = CreateCertificate("Direct-" + Guid.NewGuid(), upper, true))
                    using (var partialLeaf = CreateCertificate(ServerName, direct))
                    {
                        var partialChain = new[] { direct, upper };
                        Expect(Validate(partialLeaf, partialChain, Settings(missingRoot.Thumbprint)), false);
                        Expect(Validate(partialLeaf, partialChain, Settings(upper.Thumbprint)), false);
                        Expect(Validate(partialLeaf, partialChain, Settings(direct.Thumbprint)), true);
                    }
                });
                Run("Leaf pin is not an issuer pin", () =>
                    Expect(Validate(leaf, certificates, Settings(leaf.Thumbprint)), false));
                Run("Issuer rollover and ordinal case-insensitive matching", () =>
                    Expect(Validate(leaf, certificates, Settings(wrongIssuer.Thumbprint + ", " + issuer.Thumbprint.ToLowerInvariant(),
                        name: ServerName.ToUpperInvariant())), true));
                Run("Name and issuer must match the same entry", () =>
                {
                    var settings = new RemoteX509SecuritySettings(
                        new List<X509Name>
                        {
                            new X509Name(ServerName, wrongIssuer.Thumbprint),
                            new X509Name("other.example", issuer.Thumbprint),
                        }, false, true);
                    Expect(Validate(leaf, certificates, settings), false);
                });
                Run("Name cannot borrow a root pin from another entry", () =>
                {
                    var settings = new RemoteX509SecuritySettings(
                        new List<X509Name>
                        {
                            new X509Name(ServerName, wrongIssuer.Thumbprint),
                            new X509Name("other.example", root.Thumbprint),
                        }, false, true);
                    Expect(Validate(leaf, certificates, settings), false);
                });
                Run("A name-only entry cannot borrow another entry's issuer trust", () =>
                {
                    var settings = new RemoteX509SecuritySettings(
                        new List<X509Name>
                        {
                            new X509Name(ServerName),
                            new X509Name("other.example", issuer.Thumbprint),
                        }, false, true);
                    Expect(Validate(leaf, certificates, settings), false);
                });
                Run("Opt-in checks issuer even if TLS reports no errors", () =>
                    Expect(Validate(leaf, certificates, Settings(wrongIssuer.Thumbprint), SslPolicyErrors.None), false));
                Run("Opt-in checks name even if TLS reports no errors", () =>
                    Expect(Validate(leaf, certificates, Settings(issuer.Thumbprint, name: "other.example"), SslPolicyErrors.None), false));
                Run("Existing trusted-TLS fast path remains unchanged", () =>
                    Expect(Validate(leaf, certificates, Settings(wrongIssuer.Thumbprint, enabled: false), SslPolicyErrors.None), true));
                Run("Existing leaf-thumbprint validation remains unchanged", () =>
                    Expect(Validate(leaf, certificates, new RemoteX509SecuritySettings(new List<string> { leaf.Thumbprint })), true));
                Run("Missing certificate and combined policy errors fail closed", () =>
                {
                    using (var chain = BuildChain(leaf, certificates))
                    {
                        var validator = new ServerCertificateValidator(pinned);
                        Expect(validator.ValidateCertificate(null, null, chain, SslPolicyErrors.None), false);
                        Expect(validator.ValidateCertificate(null, leaf, null, SslPolicyErrors.None), false);
                        Expect(validator.ValidateCertificate(null, leaf, chain,
                            SslPolicyErrors.RemoteCertificateNotAvailable | SslPolicyErrors.RemoteCertificateChainErrors), false);
                    }
                });
                Run("Missing issuer cannot be replaced by a thumbprint string", () =>
                {
                    using (var missingRoot = CreateCertificate("MissingRoot-" + Guid.NewGuid(), null, true))
                    using (var missingLeaf = CreateCertificate(ServerName, missingRoot))
                    {
                        Expect(Validate(missingLeaf, new X509Certificate2[0], Settings(missingRoot.Thumbprint)), false);
                    }
                });
                Run("Self-signed leaf is not a pinned issuer chain", () =>
                {
                    using (var selfSigned = CreateCertificate(ServerName, null))
                    {
                        Expect(Validate(selfSigned, new X509Certificate2[0], Settings(selfSigned.Thumbprint)), false);
                    }
                });
                Run("Expired leaf is rejected", () =>
                {
                    using (var expired = CreateCertificate(ServerName, issuer, notBefore: -10, notAfter: -1))
                    {
                        Expect(Validate(expired, certificates, pinned), false);
                        Expect(Validate(expired, certificates, Settings(root.Thumbprint)), false);
                    }
                });
                Run("Not-yet-valid leaf is rejected", () =>
                {
                    using (var future = CreateCertificate(ServerName, issuer, notBefore: 1, notAfter: 10))
                    {
                        Expect(Validate(future, certificates, pinned), false);
                        Expect(Validate(future, certificates, Settings(root.Thumbprint)), false);
                    }
                });
                Run("Expired pinned issuer is rejected", () =>
                {
                    using (var expiredIssuer = CreateCertificate("ExpiredIssuer-" + Guid.NewGuid(), root, true, -10, -1))
                    using (var validLeaf = CreateCertificate(ServerName, expiredIssuer))
                    {
                        Expect(Validate(validLeaf, new[] { expiredIssuer, root }, Settings(expiredIssuer.Thumbprint)), false);
                        Expect(Validate(validLeaf, new[] { expiredIssuer, root }, Settings(root.Thumbprint)), false);
                    }
                });
                Run("Expired pinned root is rejected", () =>
                {
                    using (var expiredRoot = CreateCertificate("ExpiredRoot-" + Guid.NewGuid(), null, true, -10, -1))
                    using (var validIssuer = CreateCertificate("ValidIssuer-" + Guid.NewGuid(), expiredRoot, true))
                    using (var validLeaf = CreateCertificate(ServerName, validIssuer))
                    {
                        Expect(Validate(validLeaf, new[] { validIssuer, expiredRoot }, Settings(expiredRoot.Thumbprint)), false);
                    }
                });
                Run("Invalid leaf signature is rejected", () =>
                {
                    var bytes = leaf.RawData;
                    bytes[bytes.Length - 1] ^= 1;
                    using (var corrupt = new X509Certificate2(bytes))
                    {
                        Expect(Validate(corrupt, certificates, pinned), false);
                        Expect(Validate(corrupt, certificates, Settings(root.Thumbprint)), false);
                    }
                });
                Run("Invalid issuer signature is rejected", () =>
                {
                    var bytes = issuer.RawData;
                    bytes[bytes.Length - 1] ^= 1;
                    using (var corruptIssuer = new X509Certificate2(bytes))
                    {
                        Expect(Validate(leaf, new[] { corruptIssuer, root }, Settings(corruptIssuer.Thumbprint)), false);
                        Expect(Validate(leaf, new[] { corruptIssuer, root }, Settings(root.Thumbprint)), false);
                    }
                });
                Run("Client-only EKU is rejected for a server", () =>
                {
                    using (var clientOnly = CreateCertificate(ServerName, issuer, serverAuthentication: false))
                    {
                        Expect(Validate(clientOnly, certificates, pinned), false);
                        Expect(Validate(clientOnly, certificates, Settings(root.Thumbprint)), false);
                    }
                });
                Run("Unsupported critical extension is rejected", () =>
                {
                    using (var critical = CreateCertificate(ServerName, issuer, unknownCriticalExtension: true))
                    {
                        Expect(Validate(critical, certificates, pinned), false);
                        Expect(Validate(critical, certificates, Settings(root.Thumbprint)), false);
                    }
                });
                Run("Issuer path-length constraints are enforced", () =>
                {
                    using (var restricted = CreateCertificate("Restricted-" + Guid.NewGuid(), root, true, pathLength: 0))
                    using (var subordinate = CreateCertificate("Subordinate-" + Guid.NewGuid(), restricted, true))
                    using (var invalidLeaf = CreateCertificate(ServerName, subordinate))
                    {
                        Expect(Validate(invalidLeaf, new[] { subordinate, restricted, root }, Settings(subordinate.Thumbprint)), false);
                        Expect(Validate(invalidLeaf, new[] { subordinate, restricted, root }, Settings(root.Thumbprint)), false);
                    }
                });
                Run("Non-CA signer is rejected even when pinned", () =>
                {
                    using (var nonCa = CreateCertificate("NotCA-" + Guid.NewGuid(), root))
                    using (var invalidLeaf = CreateCertificate(ServerName, nonCa))
                    {
                        Expect(Validate(invalidLeaf, new[] { nonCa, root }, Settings(nonCa.Thumbprint)), false);
                        Expect(Validate(invalidLeaf, new[] { nonCa, root }, Settings(root.Thumbprint)), false);
                    }
                });
                Run("Supplied chain for a different leaf does not bypass signature verification", () =>
                {
                    using (var chain = BuildChain(leaf, certificates))
                    using (var differentLeaf = CreateCertificate(ServerName, wrongIssuer))
                    {
                        Expect(new ServerCertificateValidator(pinned).ValidateCertificate(
                            null, differentLeaf, chain, SslPolicyErrors.None), false);
                    }
                });
                Run("Inherited permissive policy cannot bypass expiry", () =>
                {
                    using (var expired = CreateCertificate(ServerName, issuer, notBefore: -10, notAfter: -1))
                    using (var chain = BuildChain(leaf, certificates))
                    {
                        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;
                        chain.ChainPolicy.VerificationTime = DateTime.Now.AddDays(-5);
                        Expect(new ServerCertificateValidator(pinned).ValidateCertificate(null, expired, chain, SslPolicyErrors.None), false);
                    }
                });
                Run("Refreshing settings can enable and disable scoped trust", () =>
                {
                    using (var chain = BuildChain(leaf, certificates))
                    {
                        var validator = new ServerCertificateValidator(Settings(issuer.Thumbprint, enabled: false));
                        Expect(validator.ValidateCertificate(null, leaf, chain, SslPolicyErrors.RemoteCertificateChainErrors), false);
                        validator.UpdateSecuritySettings(pinned);
                        Expect(validator.ValidateCertificate(null, leaf, chain, SslPolicyErrors.RemoteCertificateChainErrors), true);
                        validator.UpdateSecuritySettings(Settings(root.Thumbprint));
                        Expect(validator.ValidateCertificate(null, leaf, chain, SslPolicyErrors.RemoteCertificateChainErrors), true);
                        validator.UpdateSecuritySettings(Settings(wrongIssuer.Thumbprint));
                        Expect(validator.ValidateCertificate(null, leaf, chain, SslPolicyErrors.RemoteCertificateChainErrors), false);
                        validator.UpdateSecuritySettings(Settings(issuer.Thumbprint, enabled: false));
                        Expect(validator.ValidateCertificate(null, leaf, chain, SslPolicyErrors.RemoteCertificateChainErrors), false);
                    }
                });
                Run("Framework HTTP callback uses scoped trust and surfaces authentication failures", () =>
                    CheckHttpCallback(leaf, certificates, pinned, Settings(wrongIssuer.Thumbprint)));
                Run("Framework HTTP callback supports root pinning", () =>
                    CheckHttpCallback(leaf, certificates, Settings(root.Thumbprint), Settings(wrongIssuer.Thumbprint)));
                Run("Renamed opt-in property defaults to false", () =>
                {
                    var names = new List<X509Name> { new X509Name(ServerName, root.Thumbprint) };
                    Expect(new RemoteX509SecuritySettings(names).AllowUntrustedRootWithPinnedIssuer, false);
                    Expect(new RemoteX509SecuritySettings(new List<string> { leaf.Thumbprint }).AllowUntrustedRootWithPinnedIssuer, false);
                    Expect(Settings(root.Thumbprint).AllowUntrustedRootWithPinnedIssuer, true);
                });
                Run("Revocation and combined error masks remain fail-closed", CheckErrorMasks);
                Run("Validation does not mutate the caller's chain policy", () =>
                {
                    using (var chain = BuildChain(leaf, certificates))
                    {
                        var extraCount = chain.ChainPolicy.ExtraStore.Count;
                        var statuses = chain.ChainStatus.Select(s => s.Status).ToArray();
                        Expect(new ServerCertificateValidator(pinned).ValidateCertificate(
                            null, leaf, chain, SslPolicyErrors.RemoteCertificateChainErrors), true);
                        Expect(chain.ChainPolicy.ExtraStore.Count == extraCount, true);
                        Expect(chain.ChainPolicy.RevocationMode == X509RevocationMode.NoCheck, true);
                        Expect(chain.ChainPolicy.VerificationFlags == X509VerificationFlags.NoFlag, true);
                        Expect(chain.ChainPolicy.ApplicationPolicy.Count == 0, true);
                        Expect(chain.ChainStatus.Select(s => s.Status).SequenceEqual(statuses), true);
                    }
                });
            }

            if (args.Contains("--public-tls"))
            {
                Run("Public-CA HTTPS remains valid with and without the opt-in", CheckPublicTls);
            }

            Console.WriteLine("{0} passed, {1} failed", passed, failed);
            return failed == 0 ? 0 : 1;
        }

        private static RemoteX509SecuritySettings Settings(string issuer, bool enabled = true, bool ignoreOffline = false, string name = ServerName)
        {
            return new RemoteX509SecuritySettings(new List<X509Name> { new X509Name(name, issuer) },
                ignoreCrlOfflineError: ignoreOffline, allowUntrustedRootWithPinnedIssuer: enabled);
        }

        private static X509Chain BuildChain(X509Certificate2 leaf, X509Certificate2[] certificates)
        {
            var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.ExtraStore.AddRange(certificates);
            chain.Build(leaf);
            return chain;
        }

        private static bool Validate(X509Certificate2 leaf, X509Certificate2[] certificates, RemoteX509SecuritySettings settings,
            SslPolicyErrors errors = SslPolicyErrors.RemoteCertificateChainErrors | SslPolicyErrors.RemoteCertificateNameMismatch)
        {
            using (var chain = BuildChain(leaf, certificates))
            {
                return new ServerCertificateValidator(settings).ValidateCertificate(null, leaf, chain, errors);
            }
        }

        private static void CheckHttpCallback(X509Certificate2 leaf, X509Certificate2[] certificates,
            RemoteX509SecuritySettings valid, RemoteX509SecuritySettings invalid)
        {
            var assembly = Assembly.Load("Microsoft.ServiceFabric.Client.Http");
            var wrapperType = assembly.GetType("Microsoft.ServiceFabric.Client.Http.HttpClientHandlerWrapper", true);
            using (var handler = new WebRequestHandler())
            using (var chain = BuildChain(leaf, certificates))
            {
                var wrapper = Activator.CreateInstance(wrapperType, handler);
                wrapperType.GetMethod("ConfigureSecuritySettings").Invoke(wrapper,
                    new object[] { new X509SecuritySettings(leaf, valid) });
                Expect(handler.ServerCertificateValidationCallback(null, leaf, chain, SslPolicyErrors.RemoteCertificateChainErrors), true);
                wrapperType.GetMethod("RefreshSecuritySettings").Invoke(wrapper,
                    new object[] { new X509SecuritySettings(leaf, invalid) });
                try
                {
                    handler.ServerCertificateValidationCallback(null, leaf, chain, SslPolicyErrors.RemoteCertificateChainErrors);
                }
                catch (AuthenticationException)
                {
                    return;
                }

                throw new InvalidOperationException("HTTP callback did not report authentication failure.");
            }
        }

        private static void CheckErrorMasks()
        {
            var method = typeof(ServerCertificateValidator).GetMethod("HasOnlyAllowedChainErrors",
                BindingFlags.NonPublic | BindingFlags.Instance, null,
                new[] { typeof(IEnumerable<X509ChainStatus>), typeof(X509ChainStatusFlags) }, null);
            foreach (var ignoreOffline in new[] { false, true })
            {
                var validator = new ServerCertificateValidator(Settings("pin", ignoreOffline: ignoreOffline));
                var trustErrors = X509ChainStatusFlags.UntrustedRoot | X509ChainStatusFlags.PartialChain;
                foreach (X509ChainStatusFlags failure in Enum.GetValues(typeof(X509ChainStatusFlags)))
                {
                    var statuses = new[] { new X509ChainStatus { Status = X509ChainStatusFlags.UntrustedRoot | failure } };
                    var expected = (failure & ~trustErrors) == 0 ||
                        (ignoreOffline && failure == X509ChainStatusFlags.OfflineRevocation);
                    Expect((bool)method.Invoke(validator, new object[] { statuses, trustErrors }), expected);
                }

                var offline = new[]
                {
                    new X509ChainStatus { Status = X509ChainStatusFlags.OfflineRevocation },
                    new X509ChainStatus { Status = X509ChainStatusFlags.RevocationStatusUnknown },
                };
                Expect((bool)method.Invoke(validator, new object[] { offline, trustErrors }), ignoreOffline);
                var revoked = offline.Concat(new[] { new X509ChainStatus { Status = X509ChainStatusFlags.Revoked } }).ToArray();
                Expect((bool)method.Invoke(validator, new object[] { revoked, trustErrors }), false);
            }
        }

        private static void CheckPublicTls()
        {
            var checkedCertificate = false;
            using (var handler = new WebRequestHandler())
            {
                handler.ServerCertificateValidationCallback = (sender, certificate, chain, errors) =>
                {
                    Expect(errors == SslPolicyErrors.None, true, "Public endpoint TLS must be trusted before custom validation");
                    using (var peer = new X509Certificate2(certificate))
                    {
                        var name = peer.GetNameInfo(X509NameType.DnsName, false);
                        Expect(new ServerCertificateValidator(Settings(null, enabled: false, name: name))
                            .ValidateCertificate(sender, peer, chain, errors), true, "Legacy public-CA validation");
                        Expect(new ServerCertificateValidator(Settings(null, name: name))
                            .ValidateCertificate(sender, peer, chain, errors), true, "Opt-in public-CA validation without a pin");
                        var issuer = chain.ChainElements[1].Certificate.Thumbprint;
                        Expect(new ServerCertificateValidator(Settings(issuer, name: name))
                            .ValidateCertificate(sender, peer, chain, errors), true, "Opt-in public-CA validation with a pin");
                        var root = chain.ChainElements[chain.ChainElements.Count - 1].Certificate.Thumbprint;
                        Expect(new ServerCertificateValidator(Settings(root, name: name))
                            .ValidateCertificate(sender, peer, chain, errors), true, "Opt-in public-CA validation with a root pin");
                        Expect(new ServerCertificateValidator(Settings("incorrect-issuer", name: name))
                            .ValidateCertificate(sender, peer, chain, errors), false);
                    }

                    checkedCertificate = true;
                    return true;
                };
                using (var client = new HttpClient(handler))
                using (var request = new HttpRequestMessage(HttpMethod.Head, "https://www.microsoft.com/"))
                using (var response = client.SendAsync(request).GetAwaiter().GetResult())
                {
                    Expect(checkedCertificate, true);
                }
            }
        }

        private static X509Certificate2 CreateCertificate(string name, X509Certificate2 issuer, bool isCa = false,
            int notBefore = -30, int notAfter = 30, bool serverAuthentication = true,
            bool unknownCriticalExtension = false, int? pathLength = null)
        {
            using (var key = RSA.Create(2048))
            {
                var request = new CertificateRequest("CN=" + name, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                request.CertificateExtensions.Add(new X509BasicConstraintsExtension(isCa, pathLength.HasValue, pathLength.GetValueOrDefault(), true));
                request.CertificateExtensions.Add(new X509KeyUsageExtension(
                    isCa ? X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign : X509KeyUsageFlags.DigitalSignature, true));
                request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
                if (unknownCriticalExtension)
                {
                    request.CertificateExtensions.Add(new X509Extension("1.2.3.4.5.6.7.8.9", new byte[] { 5, 0 }, true));
                }
                if (!isCa)
                {
                    request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                        new OidCollection { new Oid(serverAuthentication ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2") }, true));
                }

                var start = DateTimeOffset.UtcNow.AddDays(notBefore);
                var end = DateTimeOffset.UtcNow.AddDays(notAfter);
                if (issuer == null)
                {
                    return request.CreateSelfSigned(start, end);
                }

                using (var issuerKey = issuer.GetRSAPrivateKey())
                using (var certificate = request.Create(issuer.SubjectName,
                    X509SignatureGenerator.CreateForRSA(issuerKey, RSASignaturePadding.Pkcs1), start, end, Guid.NewGuid().ToByteArray()))
                {
                    return certificate.CopyWithPrivateKey(key);
                }
            }
        }

        private static void Expect(bool actual, bool expected, string context = null)
        {
            if (actual != expected)
            {
                throw new InvalidOperationException(context + ": Expected " + expected + ", got " + actual);
            }
        }

        private static void Run(string name, Action test)
        {
            try
            {
                test();
                passed++;
                Console.WriteLine("PASS: " + name);
            }
            catch (Exception exception)
            {
                failed++;
                Console.Error.WriteLine("FAIL: " + name + Environment.NewLine + exception);
            }
        }
    }
}
