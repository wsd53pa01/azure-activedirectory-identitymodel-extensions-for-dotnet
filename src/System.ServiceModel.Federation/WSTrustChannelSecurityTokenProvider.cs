// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma warning disable 1591

using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.IO;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Protocols.WsAddressing;
using Microsoft.IdentityModel.Protocols.WsPolicy;
using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace System.ServiceModel.Federation
{

    /// <summary>
    /// Custom WSTrustChannelSecurityTokenProvider that returns a SAML assertion
    /// </summary>
    public class WSTrustChannelSecurityTokenProvider : SecurityTokenProvider
    {
        public const int DefaultPublicKeySize = 1024;
        private const string Namespace = "http://schemas.microsoft.com/ws/2006/05/servicemodel/securitytokenrequirement";
        private const string IssuedSecurityTokenParametersProperty = Namespace + "/IssuedSecurityTokenParameters";
        private const string SecurityAlgorithmSuiteProperty = Namespace + "/SecurityAlgorithmSuite";
        private const string TargetAddressProperty = Namespace + "/TargetAddress";

        internal const bool DefaultCacheIssuedTokens = true;
        internal static readonly TimeSpan DefaultMaxIssuedTokenCachingTime = TimeSpan.MaxValue;
        internal const int DefaultIssuedTokenRenewalThresholdPercentage = 60;

        private TimeSpan _maxIssuedTokenCachingTime = DefaultMaxIssuedTokenCachingTime;
        private int _issuedTokenRenewalThresholdPercentage = DefaultIssuedTokenRenewalThresholdPercentage;
        private IDistributedCache _cache;
        private readonly WsTrustRequest _wsTrustRequest;
        private readonly ChannelFactory<IRequestChannel> _channelFactory;
        private readonly SecurityAlgorithmSuite _securityAlgorithmSuite;

        public WSTrustChannelSecurityTokenProvider(SecurityTokenRequirement tokenRequirement) : this(tokenRequirement, null)
        { }

        public WSTrustChannelSecurityTokenProvider(SecurityTokenRequirement tokenRequirement, string requestContext)
        {
            SecurityTokenRequirement = tokenRequirement ?? throw new ArgumentNullException(nameof(tokenRequirement));
            SecurityTokenRequirement.TryGetProperty(SecurityAlgorithmSuiteProperty, out _securityAlgorithmSuite);
            _cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

            IssuedSecurityTokenParameters issuedTokenParameters = SecurityTokenRequirement.GetProperty<IssuedSecurityTokenParameters>(IssuedSecurityTokenParametersProperty);

            RequestContext = string.IsNullOrEmpty(requestContext) ? Guid.NewGuid().ToString() : requestContext;
            _wsTrustRequest = CreateWsTrustRequest(issuedTokenParameters);
            _channelFactory = CreateChannelFactory(issuedTokenParameters);
        }

        protected virtual ChannelFactory<IRequestChannel> CreateChannelFactory(IssuedSecurityTokenParameters issuedTokenParameters)
        {
            var factory = new ChannelFactory<IRequestChannel>(issuedTokenParameters.IssuerBinding, issuedTokenParameters.IssuerAddress);

            // Temporary as test STS is not trusted.
            // This code should be removed.
            factory.Credentials.ServiceCertificate.Authentication.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None;
            factory.Credentials.ServiceCertificate.SslCertificateAuthentication = new X509ServiceCertificateAuthentication();
            factory.Credentials.ServiceCertificate.SslCertificateAuthentication.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None;

            return factory;
        }

        private WsTrustRequest CreateWsTrustRequest(IssuedSecurityTokenParameters issuedTokenParameters)
        {
            EndpointAddress target = SecurityTokenRequirement.GetProperty<EndpointAddress>(TargetAddressProperty);

            // Note that the GetCacheKeyFromRequest method needs to capture any properties that are set here.
            // If WsTrustRequest creation logic changes here, update GetCacheKeyFromRequest accordingly.
            return new WsTrustRequest(WsTrustConstants.Trust13.WsTrustActions.Issue)
            {
                AppliesTo = new AppliesTo(new EndpointReference(target.Uri.OriginalString)),
                Context = RequestContext,
                KeyType = issuedTokenParameters.KeyType == SecurityKeyType.AsymmetricKey
                                                        ? WsTrustKeyTypes.Trust13.PublicKey
                                                        : issuedTokenParameters.KeyType == SecurityKeyType.SymmetricKey
                                                        ? WsTrustKeyTypes.Trust13.Symmetric
                                                        : WsTrustKeyTypes.Trust13.Bearer,
                //ProofEncryption = new Microsoft.IdentityModel.Xml.SecurityTokenElement()
                RequestType = WsTrustConstants.Trust13.WsTrustActions.Issue,
                TokenType = SecurityTokenRequirement.TokenType
            };
        }

        public SecurityTokenRequirement SecurityTokenRequirement
        {
            get;
        }

        /// <summary>
        /// A context string used in outgoing WsTrustRequests that may be useful for correlating requests.
        /// </summary>
        public string RequestContext
        {
            get;
        }

        /// <summary>
        /// Gets or sets the cache used for storing issued security tokens.
        /// </summary>
        protected IDistributedCache IssuedTokensCache
        {
            get => _cache;
            set => _cache = value ?? throw new ArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Gets or sets whether issued tokens should be cached and reused within their expiry periods.
        /// </summary>
        public bool CacheIssuedTokens { get; set; } = DefaultCacheIssuedTokens;

        /// <summary>
        /// Gets or sets the maximum time an issued token will be cached before renewing it.
        /// </summary>
        public TimeSpan MaxIssuedTokenCachingTime
        {
            get => _maxIssuedTokenCachingTime;
            set => _maxIssuedTokenCachingTime = value <= TimeSpan.Zero
                ? throw new ArgumentOutOfRangeException(nameof(value), "TimeSpan must be greater than TimeSpan.Zero.") // TODO - Get exception messages from resources
                : value;
        }

        /// <summary>
        /// Gets or sets the percentage of the issued token's lifetime at which it should be renewed instead of cached.
        /// </summary>
        public int IssuedTokenRenewalThresholdPercentage
        {
            get => _issuedTokenRenewalThresholdPercentage;
            set => _issuedTokenRenewalThresholdPercentage = (value <= 0 || value > 100)
                ? throw new ArgumentOutOfRangeException(nameof(value), "Issued token renewal threshold percentage must be greater than or equal to 1 and less than or equal to 100.")
                : value;
        }

        private WsTrustResponse GetCachedResponse(WsTrustRequest request)
        {
            if (CacheIssuedTokens)
            {
                string cacheKey = GetCacheKeyFromRequest(request);
                byte[] responseBytes = IssuedTokensCache?.Get(cacheKey);

                if (responseBytes != null)
                {
                    var serializer = new WsTrustSerializer();
                    using (var reader = XmlDictionaryReader.CreateBinaryReader(responseBytes, XmlDictionaryReaderQuotas.Max))
                    {
                        var response = serializer.ReadResponse(reader);

                        if (IsSecurityTokenResponseUnexpired(response))
                        {
                            return response;
                        }
                    }
                }
            }

            return null;
        }

        private void CacheSecurityTokenResponse(WsTrustRequest request, WsTrustResponse response)
        {
            if (CacheIssuedTokens && IssuedTokensCache != null)
            {
                string cacheKey = GetCacheKeyFromRequest(request);
                var serializer = new WsTrustSerializer();

                using (var ms = new MemoryStream())
                using (var writer = XmlDictionaryWriter.CreateBinaryWriter(ms))
                {
                    serializer.WriteResponse(writer, WsTrustVersion.Trust13, response);
                    writer.Flush();
                    IssuedTokensCache?.Set(cacheKey, ms.ToArray());
                }
            }
        }

        private bool IsSecurityTokenResponseUnexpired(WsTrustResponse cachedResponse)
        {
            var responseLifetime = cachedResponse?.RequestSecurityTokenResponseCollection?[0]?.Lifetime;

            if (responseLifetime == null || responseLifetime.Expires == null)
            {
                // A null lifetime could represent an invalid response or a valid response
                // with an unspecified expiration. Similarly, a response lifetime without an expiration
                // time represents an unspecified expiration. In any of these cases, err on the side of
                // retrieving a new response instead of possibly using an invalid or expired one.
                return false;
            }

            // If a response's lifetime doesn't specify a created time, conservatively assume the response was just created.
            DateTime fromTime = responseLifetime.Created?.ToUniversalTime() ?? DateTime.UtcNow;
            DateTime toTime = responseLifetime.Expires.Value.ToUniversalTime();

            long interval = toTime.Ticks - fromTime.Ticks;
            long effectiveInterval = (long)((IssuedTokenRenewalThresholdPercentage / (double)100) * interval);
            DateTime effectiveExpiration = AddTicks(fromTime, Math.Min(effectiveInterval, MaxIssuedTokenCachingTime.Ticks));

            return effectiveExpiration > DateTime.UtcNow;
        }

        private DateTime AddTicks(DateTime time, long ticks)
        {
            if (ticks > 0 && DateTime.MaxValue.Subtract(time).Ticks <= ticks)
            {
                return DateTime.MaxValue;
            }
            if (ticks < 0 && time.Subtract(DateTime.MinValue).Ticks <= -ticks)
            {
                return DateTime.MinValue;
            }
            return time.AddTicks(ticks);
        }

        /// <summary>
        /// Calls out to the STS, if necessary to get a token
        /// </summary>
        protected override System.IdentityModel.Tokens.SecurityToken GetTokenCore(TimeSpan timeout)
        {
            WsTrustResponse trustResponse = GetCachedResponse(_wsTrustRequest);
            if (trustResponse is null)
            {
                using (var memeoryStream = new MemoryStream())
                {
                    var writer = XmlDictionaryWriter.CreateTextWriter(memeoryStream, Encoding.UTF8);
                    var serializer = new WsTrustSerializer();
                    serializer.WriteRequest(writer, WsTrustVersion.Trust13, _wsTrustRequest);
                    writer.Flush();
                    var reader = XmlDictionaryReader.CreateTextReader(memeoryStream.ToArray(), XmlDictionaryReaderQuotas.Max);

                    IRequestChannel channel = _channelFactory.CreateChannel();
                    Message reply = channel.Request(Message.CreateMessage(MessageVersion.Soap12WSAddressing10, WsTrustActions.Trust13.IssueRequest, reader));
                    trustResponse = serializer.ReadResponse(reply.GetReaderAtBodyContents());

                    CacheSecurityTokenResponse(_wsTrustRequest, trustResponse);
                }
            }

            // Create GenericXmlSecurityToken
            // Assumes that token is first and Saml2SecurityToken.
            using (var stream = new MemoryStream())
            {
                var response = trustResponse.RequestSecurityTokenResponseCollection[0];
                var writer = XmlDictionaryWriter.CreateTextWriter(stream, Encoding.UTF8, false);
                var tokenHandler = new Saml2SecurityTokenHandler();
                tokenHandler.TryWriteSourceData(writer, response.RequestedSecurityToken.SecurityToken);
                writer.Flush();
                stream.Seek(0, SeekOrigin.Begin);
                var dom = new XmlDocument
                {
                    PreserveWhitespace = true
                };

                IdentityModel.Tokens.SecurityToken proofToken = GetProofToken(_wsTrustRequest, response);
                SecurityTokenReference securityTokenReference = new SecurityTokenReference
                {
                    Id = response.AttachedReference.KeyIdentifier.Value,
                    TokenType = response.AttachedReference.TokenType
                };

                var element = WsSecuritySerializer.GetXmlElement(securityTokenReference, WsTrustVersion.Trust13);
                dom.Load(new XmlTextReader(stream) { DtdProcessing = DtdProcessing.Prohibit });
                GenericXmlSecurityKeyIdentifierClause securityKeyIdentifierClause = new GenericXmlSecurityKeyIdentifierClause(element);
                return new GenericXmlSecurityToken(dom.DocumentElement,
                                                   proofToken,
                                                   DateTime.UtcNow,
                                                   DateTime.UtcNow + TimeSpan.FromDays(1),  // TODO - This should be based on response.Lifetime
                                                   securityKeyIdentifierClause,
                                                   securityKeyIdentifierClause,
                                                   null);
            }
        }

        /// <summary>
        /// Get a proof token from a WsTrust request/response pair based on section 4.4.3 of the WS-Trust 1.3 spec.
        /// How the proof token is retrieved depends on whether the requestor or issuer provide key material:
        /// Requestor   |   Issuer                  | Results
        /// -------------------------------------------------
        /// Entropy     | No key material           | No proof token returned, requestor entropy used
        /// Entropy     | Entropy                   | Computed key algorithm returned and key computed based on request and response entropy
        /// Entropy     | Rejects requestor entropy | Proof token in response used as key
        /// No entropy  | Issues key                | Proof token in response used as key
        /// No entropy  | No key material           | No proof token
        /// </summary>
        /// <param name="request">The WS-Trust request (RST).</param>
        /// <param name="response">The WS-Trust response (RSTR).</param>
        /// <returns>The proof token or null if there is no proof token.</returns>
        private BinarySecretSecurityToken GetProofToken(WsTrustRequest request, RequestSecurityTokenResponse response)
        {
            string keyType = response.KeyType ?? request.KeyType;

            if (response.RequestedProofToken?.BinarySecret != null)
            {
                // If the response includes a proof token, use it as the security token's proof token.
                // This scenario will occur if the request does not include entropy or if the issuer rejects the requestor's entropy.
                return new BinarySecretSecurityToken(response.RequestedProofToken.BinarySecret.Data);
            }
            else if (response.RequestedProofToken?.ComputedKeyAlgorithm != null)
            {
                // If the response includes a computed key algorithm, compute the proof token based on requestor and issuer entropy.
                // This scenario will occur if the requestor and issuer both provide key material.
                if (string.Equals(response.RequestedProofToken.ComputedKeyAlgorithm, WsTrustKeyTypes.Trust13.PSHA1, StringComparison.Ordinal))
                {
                    byte[] issuerEntropy = response.Entropy?.BinarySecret?.Data ?? response.Entropy?.ProtectedKey?.Secret;
                    if (issuerEntropy == null)
                    {
                        throw new InvalidOperationException("Computed key proof tokens require issuer to supply key material via entropy.");
                    }

                    byte[] requestorEntropy = request.Entropy?.BinarySecret?.Data ?? request.Entropy?.ProtectedKey?.Secret;
                    if (requestorEntropy == null)
                    {
                        throw new InvalidOperationException("Computed key proof tokens require requestor to supply key material via entropy.");
                    }

                    int keySizeInBits = response.KeySizeInBits ?? 0; // RSTR key size has precedence
                    if (keySizeInBits == 0)
                    {
                        keySizeInBits = request.KeySizeInBits ?? 0; // Followed by RST
                    }
                    if (keySizeInBits == 0)
                    {
                        keySizeInBits = string.Equals(keyType, WsTrustKeyTypes.Trust13.Symmetric, StringComparison.Ordinal)
                            ? _securityAlgorithmSuite.DefaultSymmetricKeyLength // Symmetric keys should default to a length cooresponding to the algorithm in use
                            : DefaultPublicKeySize; // Asymmetric keys default to 1024 bits
                    }
                    if (keySizeInBits == 0)
                    {
                        throw new InvalidOperationException("No key size provided.");
                    }

                    return new BinarySecretSecurityToken(KeyGenerator.ComputeCombinedKey(issuerEntropy, requestorEntropy, keySizeInBits));
                }
                else
                {
                    throw new NotSupportedException("Only PSHA1 computed keys are supported.");
                }
            }
            else if (request.Entropy != null)
            {
                // If the response does not have a proof token or computed key value, but the request proposed entropy,
                // then the requestor's entropy is used as the proof token.
                if (request.Entropy.BinarySecret != null)
                {
                    return new BinarySecretSecurityToken(request.Entropy.BinarySecret.Data);
                }
                else if (request.Entropy.ProtectedKey != null)
                {
                    return new BinarySecretSecurityToken(request.Entropy.ProtectedKey.Secret);
                }
            }

            // If we get here, then no key material has been supplied (by either issuer or requestor),
            // so there is no proof token.
            return null;
        }

        /// <summary>
        /// Create a string unique to the provided WsTrustRequest to be used for caching.
        /// </summary>
        /// <param name="request">The WsTrustRequest to be used as a cache key.</param>
        /// <returns>A deterministic string corresponding to the provided request.</returns>
        private string GetCacheKeyFromRequest(WsTrustRequest request) =>
            // For now, only a few request properties are used by WSTrustChannelSecurityTokenProvider.
            // If this list grows long in the future, it may be preferable to just serialize the request.
            // For the time being, though, this is a quicker and more succinct option.
$@"RequestType:{request.RequestType}
Context:{request.Context}
AppliesTo:{request.AppliesTo?.EndpointReference?.Uri.ToString()}
TokenType:{request.TokenType}
KeyType:{request.KeyType}";
    }
}
