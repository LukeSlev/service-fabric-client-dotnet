// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.ServiceFabric.Client
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net.Security;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading;
    using Microsoft.ServiceFabric.Common;
    using Microsoft.ServiceFabric.Common.Security;

    /// <summary>
    /// Class to verify the remote Secure Sockets Layer (SSL) certificate used for authentication.
    /// </summary>
    public class ServerCertificateValidator
    {
        /// <summary>
        /// Protects upgrading the remoteX509SecuritySettings while Cert Validation callback is in progress.
        /// </summary>
        private readonly ReaderWriterLockSlim slimRWLock = new ReaderWriterLockSlim();

        private RemoteX509SecuritySettings remoteX509SecuritySettings;

        /// <summary>
        /// Initializes a new instance of the <see cref="ServerCertificateValidator"/> class to perform remote certificate validation using <paramref name="remoteX509SecuritySettings"/>
        /// </summary>
        /// <param name="remoteX509SecuritySettings">Settings to validate remote certificate.</param>
        public ServerCertificateValidator(RemoteX509SecuritySettings remoteX509SecuritySettings)
        {
            remoteX509SecuritySettings.ThrowIfNull(nameof(remoteX509SecuritySettings));
            this.remoteX509SecuritySettings = remoteX509SecuritySettings;
        }

        /// <summary>
        /// Updates the <see cref="Microsoft.ServiceFabric.Common.Security.RemoteX509SecuritySettings"/> to validate remote certificate.
        /// </summary>
        /// /// <param name="remoteX509SecuritySettings">Settings to validate remote certificate.</param>
        public void UpdateSecuritySettings(RemoteX509SecuritySettings remoteX509SecuritySettings)
        {
            remoteX509SecuritySettings.ThrowIfNull(nameof(remoteX509SecuritySettings));
            this.slimRWLock.EnterWriteLock();
            this.remoteX509SecuritySettings = remoteX509SecuritySettings;
            this.slimRWLock.ExitWriteLock();
        }

        /// <summary>
        /// Callback to Verify the remote Secure Sockets Layer (SSL) certificate used for authentication.
        /// </summary>
        /// <param name="sender">An object that contains state information for this validation.</param>
        /// <param name="cert">The certificate used to authenticate the remote party.</param>
        /// <param name="chain">The chain of certificate authorities associated with the remote certificate.</param>
        /// <param name="sslPolicyErrors">One or more errors associated with the remote certificate.</param>
        /// <returns>
        /// A <see cref="bool"/> value that determines whether the specified certificate is accepted for authentication.
        /// </returns>
        public bool ValidateCertificate(
            object sender,
            X509Certificate2 cert,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
        {
            this.slimRWLock.EnterReadLock();
            try
            {
                // Opt-in trust must check the configured identity and issuer even when TLS reports no errors.
                if (this.remoteX509SecuritySettings.AllowUntrustedRootWithPinnedIssuer)
                {
                    return this.ValidateServerCertificateWithPinnedIssuer(cert, chain, sslPolicyErrors);
                }

                if (sslPolicyErrors == SslPolicyErrors.None)
                {
                    return true;
                }

                if (sslPolicyErrors == SslPolicyErrors.RemoteCertificateNotAvailable)
                {
                    return false;
                }

                // Call the validator function for X509Name or Thumbprints.
                if (this.remoteX509SecuritySettings.RemoteX509Names != null)
                {
                    return this.ValidateServerCertificateX509Name(cert, chain, sslPolicyErrors);
                }
                else if (this.remoteX509SecuritySettings.RemoteCertThumbprints != null)
                {
                    return this.ValidateServerCertificateWithThumbprint(cert, chain, sslPolicyErrors);
                }
            }
            finally
            {
                this.slimRWLock.ExitReadLock();
            }

            return false;
        }

        private bool ValidateServerCertificateWithPinnedIssuer(X509Certificate2 cert, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            var allowedPolicyErrors = SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateChainErrors;
            if (cert == null || chain == null || (sslPolicyErrors & ~allowedPolicyErrors) != SslPolicyErrors.None)
            {
                return false;
            }

            var matchingNames = this.remoteX509SecuritySettings.RemoteX509Names.Where(x =>
                x != null && !string.IsNullOrWhiteSpace(x.Name) &&
                (string.Equals(cert.GetNameInfo(X509NameType.SimpleName, false), x.Name, StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(cert.GetNameInfo(X509NameType.DnsName, false), x.Name, StringComparison.OrdinalIgnoreCase))).ToList();
            if (matchingNames.Count == 0)
            {
                return false;
            }

            using (var verifiedChain = new X509Chain())
            {
                // Rebuild for the actual peer certificate, without inheriting flags that suppress validation failures.
                verifiedChain.ChainPolicy.RevocationMode = chain.ChainPolicy.RevocationMode;
                verifiedChain.ChainPolicy.RevocationFlag = chain.ChainPolicy.RevocationFlag;
                verifiedChain.ChainPolicy.UrlRetrievalTimeout = chain.ChainPolicy.UrlRetrievalTimeout;
                verifiedChain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
                foreach (Oid policy in chain.ChainPolicy.ApplicationPolicy)
                {
                    // Duplicate EKUs cause Windows chain validation to report NotValidForUsage.
                    if (!verifiedChain.ChainPolicy.ApplicationPolicy.Cast<Oid>().Any(existing => existing.Value == policy.Value))
                    {
                        verifiedChain.ChainPolicy.ApplicationPolicy.Add(policy);
                    }
                }

                foreach (Oid policy in chain.ChainPolicy.CertificatePolicy)
                {
                    verifiedChain.ChainPolicy.CertificatePolicy.Add(policy);
                }

                verifiedChain.ChainPolicy.ExtraStore.AddRange(chain.ChainPolicy.ExtraStore);
                foreach (X509ChainElement element in chain.ChainElements)
                {
                    verifiedChain.ChainPolicy.ExtraStore.Add(element.Certificate);
                }

                var chainBuilt = verifiedChain.Build(cert);
                if (!chainBuilt && verifiedChain.ChainStatus.Length == 0)
                {
                    return false;
                }

                foreach (var name in matchingNames)
                {
                    var trustErrors = X509ChainStatusFlags.NoError;
                    if (name.IssuerCertThumbprint != null)
                    {
                        // A leaf thumbprint is not an issuer pin. The chain engine must verify a link to a CA.
                        if (verifiedChain.ChainElements.Count < 2)
                        {
                            continue;
                        }

                        var issuer = verifiedChain.ChainElements[1].Certificate;
                        var root = verifiedChain.ChainElements[verifiedChain.ChainElements.Count - 1].Certificate;
                        var hasPartialChain = verifiedChain.ChainStatus.Any(status =>
                            (status.Status & X509ChainStatusFlags.PartialChain) != 0);
                        var acceptablePin =
                            IsPinnedCertificateAuthority(issuer, name.IssuerCertThumbprint) ||
                            (!hasPartialChain && IsPinnedCertificateAuthority(root, name.IssuerCertThumbprint));
                        if (!acceptablePin)
                        {
                            continue;
                        }

                        // Root pins require a chain reaching that root; partial chains still require a direct issuer pin.
                        trustErrors = X509ChainStatusFlags.UntrustedRoot | X509ChainStatusFlags.PartialChain;
                    }

                    if (this.HasOnlyAllowedChainErrors(chain, trustErrors) &&
                        this.HasOnlyAllowedChainErrors(verifiedChain, trustErrors))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private static bool IsPinnedCertificateAuthority(X509Certificate2 certificate, string expectedThumbprints)
        {
            var constraints = certificate.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
            return constraints != null && constraints.CertificateAuthority &&
                expectedThumbprints.Split(',').Any(pin =>
                    string.Equals(pin.Trim(), certificate.Thumbprint, StringComparison.OrdinalIgnoreCase));
        }

        private bool HasOnlyAllowedChainErrors(X509Chain chain, X509ChainStatusFlags trustErrors)
        {
            return this.HasOnlyAllowedChainErrors(chain.ChainStatus, trustErrors) &&
                chain.ChainElements.Cast<X509ChainElement>().All(element =>
                    this.HasOnlyAllowedChainErrors(element.ChainElementStatus, trustErrors));
        }

        private bool HasOnlyAllowedChainErrors(IEnumerable<X509ChainStatus> statuses, X509ChainStatusFlags trustErrors)
        {
            var errors = statuses.Aggregate(X509ChainStatusFlags.NoError, (result, status) => result | status.Status);
            if (this.remoteX509SecuritySettings.IgnoreCrlOfflineError &&
                (errors & X509ChainStatusFlags.OfflineRevocation) != 0)
            {
                // Windows reports an offline CRL together with RevocationStatusUnknown.
                trustErrors |= X509ChainStatusFlags.OfflineRevocation | X509ChainStatusFlags.RevocationStatusUnknown;
            }

            return (errors & ~trustErrors) == X509ChainStatusFlags.NoError;
        }

        /// <summary>
        /// Function to Verify the remote certificate used using <see cref="Microsoft.ServiceFabric.Common.Security.X509Name"/>
        /// </summary>
        /// <param name="cert">The certificate used to authenticate the remote party.</param>
        /// <param name="chain">The chain of certificate authorities associated with the remote certificate.</param>
        /// <param name="sslPolicyErrors">One or more errors associated with the remote certificate.</param>
        /// <returns>
        /// A <see cref="bool"/> value that determines whether the specified certificate is accepted for authentication.
        /// </returns>
        private bool ValidateServerCertificateX509Name(X509Certificate2 cert, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            // SelfSigned certificates will only be verified with X509 name when chain build succeeds.
            // so it must be copied to TrustedRoot or TrustedPeople
            if ((sslPolicyErrors & SslPolicyErrors.RemoteCertificateChainErrors) ==
                SslPolicyErrors.RemoteCertificateChainErrors)
            {
                // When matching with subject name, Only CrlOffline can be ignored if specified in settings.
                if (!this.remoteX509SecuritySettings.IgnoreCrlOfflineError)
                {
                    return false;
                }
                else
                {
                    // if errors other than OfflineRevocation, return false;
                    if (
                        chain.ChainStatus.Any(
                            chainStatus => chainStatus.Status != X509ChainStatusFlags.OfflineRevocation))
                    {
                        return false;
                    }

                    // only OfflineRevocation was found, continue with validation.
                }
            }

            foreach (var x509Name in this.remoteX509SecuritySettings.RemoteX509Names)
            {
                if (cert.GetNameInfo(X509NameType.SimpleName, false).Equals(x509Name.Name, StringComparison.CurrentCultureIgnoreCase) ||
                    cert.GetNameInfo(X509NameType.DnsName, false).Equals(x509Name.Name, StringComparison.CurrentCultureIgnoreCase))
                {
                    // if issuer thumbprint is specified verify it.
                    if (x509Name.IssuerCertThumbprint != null)
                    {
                        // validate issuer thumbprint against all pairs of RemoteX509Names
                        if (this.IsServerCertIssuerThumbprintValid(chain, x509Name.IssuerCertThumbprint))
                        {
                            return true;
                        }
                    }
                    else
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private bool IsServerCertIssuerThumbprintValid(X509Chain chain, string expectedIssuerThumbprints)
        {
                var issuers = expectedIssuerThumbprints.ToLower().Split(',');

                // SelfSigned cert matches with index 0, CA signed matches with index 1.
                var thumbprint = chain.ChainElements[0].Certificate.Thumbprint.ToLower();

                if (thumbprint != null && issuers.Contains(thumbprint))
                {
                    return true;
                }

                // Not self-signed, check if its CA signed. Should have at least one issuer
                if (chain.ChainElements.Count < 2)
                {
                    return false;
                }

                thumbprint = chain.ChainElements[1].Certificate.Thumbprint.ToLower();

                return thumbprint != null && issuers.Contains(thumbprint);
        }

        /// <summary>
        /// Function to Verify the remote certificate using thumbprints.
        /// </summary>
        /// <param name="cert">The certificate used to authenticate the remote party.</param>
        /// <param name="chain">The chain of certificate authorities associated with the remote certificate.</param>
        /// <param name="sslPolicyErrors">One or more errors associated with the remote certificate.</param>
        /// <returns>
        /// A <see cref="bool"/> value that determines whether the specified certificate is accepted for authentication.
        /// </returns>
        private bool ValidateServerCertificateWithThumbprint(X509Certificate2 cert, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if ((sslPolicyErrors & SslPolicyErrors.RemoteCertificateChainErrors) ==
                SslPolicyErrors.RemoteCertificateChainErrors)
            {
                // When matching with thumbprint name, following chain building errors can be ignored for validating Server certificates.
                var nonFatalError = X509ChainStatusFlags.UntrustedRoot |
                                    X509ChainStatusFlags.RevocationStatusUnknown |
                                    X509ChainStatusFlags.PartialChain;

                // Ignore CrlOffline if specified in settings.
                if (this.remoteX509SecuritySettings.IgnoreCrlOfflineError)
                {
                    nonFatalError |= X509ChainStatusFlags.OfflineRevocation;
                }

                // only ignore non-fatal chain errors.
                if (chain.ChainStatus.Any(x => (x.Status & (~nonFatalError)) != X509ChainStatusFlags.NoError))
                {
                    return false;
                }
            }

            return this.remoteX509SecuritySettings.RemoteCertThumbprints.Any(thumbprint =>
                cert.Thumbprint != null && cert.Thumbprint.Equals(thumbprint, StringComparison.OrdinalIgnoreCase));
        }
    }
}
