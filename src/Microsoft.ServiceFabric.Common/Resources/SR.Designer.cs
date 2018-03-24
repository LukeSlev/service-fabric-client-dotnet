﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace Microsoft.ServiceFabric.Common.Resources {
    using System;
    
    
    /// <summary>
    ///   A strongly-typed resource class, for looking up localized strings, etc.
    /// </summary>
    // This class was auto-generated by the StronglyTypedResourceBuilder
    // class via a tool like ResGen or Visual Studio.
    // To add or remove a member, edit your .ResX file then rerun ResGen
    // with the /str option, or rebuild your VS project.
    [global::System.CodeDom.Compiler.GeneratedCodeAttribute("System.Resources.Tools.StronglyTypedResourceBuilder", "4.0.0.0")]
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
    [global::System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
    internal class SR {
        
        private static global::System.Resources.ResourceManager resourceMan;
        
        private static global::System.Globalization.CultureInfo resourceCulture;
        
        [global::System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1811:AvoidUncalledPrivateCode")]
        internal SR() {
        }
        
        /// <summary>
        ///   Returns the cached ResourceManager instance used by this class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Resources.ResourceManager ResourceManager {
            get {
                if (object.ReferenceEquals(resourceMan, null)) {
                    global::System.Resources.ResourceManager temp = new global::System.Resources.ResourceManager("Microsoft.ServiceFabric.Common.Resources.SR", typeof(SR).Assembly);
                    resourceMan = temp;
                }
                return resourceMan;
            }
        }
        
        /// <summary>
        ///   Overrides the current thread's CurrentUICulture property for all
        ///   resource lookups using this strongly typed resource class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Globalization.CultureInfo Culture {
            get {
                return resourceCulture;
            }
            set {
                resourceCulture = value;
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Application name must begin with fabric..
        /// </summary>
        internal static string ErrorAppNameDoesntBeginWithFabric {
            get {
                return ResourceManager.GetString("ErrorAppNameDoesntBeginWithFabric", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Application name begins with fabric://, it cannot have authority name in it..
        /// </summary>
        internal static string ErrorAppNameHasAuthorityName {
            get {
                return ResourceManager.GetString("ErrorAppNameHasAuthorityName", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Application name has invalid characters, It cannot have following invalid characters {0}..
        /// </summary>
        internal static string ErrorAppNameHasInvalidChars {
            get {
                return ResourceManager.GetString("ErrorAppNameHasInvalidChars", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Application name cannot have a trailing &quot;/&quot;..
        /// </summary>
        internal static string ErrorAppNameHasTrailingSlash {
            get {
                return ResourceManager.GetString("ErrorAppNameHasTrailingSlash", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Provided collection cannot be empty..
        /// </summary>
        internal static string ErrorCollectionCannotBeEmpty {
            get {
                return ResourceManager.GetString("ErrorCollectionCannotBeEmpty", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to {0} cannot be an empty list..
        /// </summary>
        internal static string ErrorEmptyList {
            get {
                return ResourceManager.GetString("ErrorEmptyList", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Value must be less than or equal to {0}..
        /// </summary>
        internal static string ErrorLessThanInclusiveMax {
            get {
                return ResourceManager.GetString("ErrorLessThanInclusiveMax", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Value must be greater than or equal to {0}..
        /// </summary>
        internal static string ErrorLessThanInclusiveMin {
            get {
                return ResourceManager.GetString("ErrorLessThanInclusiveMin", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to claimsToken cannot be null or empty string or consist only of whitespaces..
        /// </summary>
        internal static string ErrorLocalClaims {
            get {
                return ResourceManager.GetString("ErrorLocalClaims", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to NameDescription must begin with fabric..
        /// </summary>
        internal static string ErrorNameDoesntBeginWithFabric {
            get {
                return ResourceManager.GetString("ErrorNameDoesntBeginWithFabric", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to NameDescription begins with fabric://, it cannot have authority name in it..
        /// </summary>
        internal static string ErrorNameHasAuthorityName {
            get {
                return ResourceManager.GetString("ErrorNameHasAuthorityName", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to NameDescription has invalid characters, It cannot have following invalid characters {0}..
        /// </summary>
        internal static string ErrorNameHasInvalidChars {
            get {
                return ResourceManager.GetString("ErrorNameHasInvalidChars", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to NameDescription cannot have a trailing &quot;/&quot;..
        /// </summary>
        internal static string ErrorNameHasTrailingSlash {
            get {
                return ResourceManager.GetString("ErrorNameHasTrailingSlash", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Value must be between {0} and {1}..
        /// </summary>
        internal static string ErrorOutOfInclusiveRange {
            get {
                return ResourceManager.GetString("ErrorOutOfInclusiveRange", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Service name must begin with fabric..
        /// </summary>
        internal static string ErrorServiceNameDoesntBeginWithFabric {
            get {
                return ResourceManager.GetString("ErrorServiceNameDoesntBeginWithFabric", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Service name begins with fabric://, it cannot have authority name in it..
        /// </summary>
        internal static string ErrorServiceNameHasAuthorityName {
            get {
                return ResourceManager.GetString("ErrorServiceNameHasAuthorityName", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Service name has invalid characters, It cannot have following invalid characters {0}..
        /// </summary>
        internal static string ErrorServiceNameHasInvalidChars {
            get {
                return ResourceManager.GetString("ErrorServiceNameHasInvalidChars", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Service name cannot have a trailing &quot;/&quot;..
        /// </summary>
        internal static string ErrorServiceNameHasTrailingSlash {
            get {
                return ResourceManager.GetString("ErrorServiceNameHasTrailingSlash", resourceCulture);
            }
        }
    }
}