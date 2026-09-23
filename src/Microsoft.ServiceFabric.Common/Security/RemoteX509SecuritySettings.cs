// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.ServiceFabric.Common.Security
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Microsoft.ServiceFabric.Common.Resources;

    /// <summary>
    /// Represents X509 certificate security settings of remote machine.
    /// </summary>
    public class RemoteX509SecuritySettings
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RemoteX509SecuritySettings" /> class.
        /// </summary>
        /// <param name="remoteX509Names">Expected <see cref="Microsoft.ServiceFabric.Common.Security.X509Name"/> names of server certificate.</param>
        /// <param name="ignoreCrlOfflineError">Flag to ignore Crl offline error when verifying remote certificate, default value is false.</param>
        /// <remarks>Use this constructor to verify server certificate with server common name and issuer thumbprint.</remarks>
        public RemoteX509SecuritySettings(IList<X509Name> remoteX509Names, bool ignoreCrlOfflineError = false)
            : this(remoteX509Names, ignoreCrlOfflineError, false)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RemoteX509SecuritySettings" /> class with optional per-client issuer trust.
        /// </summary>
        /// <param name="remoteX509Names">Expected server certificate names and optional direct issuer or root CA thumbprints.</param>
        /// <param name="ignoreCrlOfflineError">Whether to ignore offline revocation failures, but not revoked certificates.</param>
        /// <param name="allowUntrustedRootWithPinnedIssuer">Whether a matching direct issuer or root CA pin may replace system root trust. Default constructors do not enable this option.</param>
        /// <remarks>
        /// This option still requires a valid server certificate chain and matching name. The pinned CA certificate must be
        /// available in the built chain. Root pins require a chain reaching that root; partial chains require a direct issuer pin.
        /// Entries without an issuer pin still require a normally trusted chain.
        /// </remarks>
        public RemoteX509SecuritySettings(IList<X509Name> remoteX509Names, bool ignoreCrlOfflineError, bool allowUntrustedRootWithPinnedIssuer)
        {
            if (remoteX509Names == null)
            {
                throw new ArgumentNullException(nameof(remoteX509Names));
            }

            if (!remoteX509Names.Any())
            {
                throw new ArgumentException(string.Format(SR.ErrorEmptyList, nameof(remoteX509Names)));
            }

            this.RemoteX509Names = remoteX509Names;
            this.IgnoreCrlOfflineError = ignoreCrlOfflineError;
            this.AllowUntrustedRootWithPinnedIssuer = allowUntrustedRootWithPinnedIssuer;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RemoteX509SecuritySettings" /> class.
        /// </summary>
        /// <param name="remoteCertThumbprints">Certificate thumbprints of server certificate.</param>
        /// <param name="ignoreCrlOfflineError">Flag to ignore Crl offline error when verifying remote certificate, default value is false.</param>
        /// <remarks>Use this constructor to verify server certificate with thumbprint.</remarks>
        public RemoteX509SecuritySettings(IList<string> remoteCertThumbprints, bool ignoreCrlOfflineError = false)
        {
            if (remoteCertThumbprints == null)
            {
                throw new ArgumentNullException(nameof(remoteCertThumbprints));
            }

            if (!remoteCertThumbprints.Any())
            {
                throw new ArgumentException(string.Format(SR.ErrorEmptyList, nameof(remoteCertThumbprints)));
            }

            this.RemoteCertThumbprints = remoteCertThumbprints.Select(x => x.Replace(" ", string.Empty)).ToList();
            this.IgnoreCrlOfflineError = ignoreCrlOfflineError;
        }

        /// <summary>
        /// Gets the list of X509Name to validate remote certificate.
        /// </summary>
        /// <value>
        /// List of <see cref="X509Name"/> to validate remote certificate.
        /// </value>
        public IList<X509Name> RemoteX509Names { get; }

        /// <summary>
        /// Gets the certificate thumbprints of server certificate.
        /// </summary>
        /// <value>
        /// Certificate thumbprints of server certificate.
        /// </value>
        public IList<string> RemoteCertThumbprints { get; }

        /// <summary>
        /// Gets a value indicating whether to ignore Crl offline error when verifying remote certificate. 
        /// </summary>
        /// <value>
        /// <see cref="bool"/> indicating whether to ignore Crl offline error when verifying remote certificate. 
        /// </value>
        public bool IgnoreCrlOfflineError { get; }

        /// <summary>
        /// Gets a value indicating whether a matching name and direct issuer or root CA pin may replace system root trust for this client.
        /// </summary>
        /// <remarks>
        /// Does not disable signature, validity, usage, or revocation validation. Without a matching issuer pin,
        /// unknown authorities and incomplete chains are rejected. Existing constructors leave this option disabled.
        /// </remarks>
        public bool AllowUntrustedRootWithPinnedIssuer { get; }
    }
}
