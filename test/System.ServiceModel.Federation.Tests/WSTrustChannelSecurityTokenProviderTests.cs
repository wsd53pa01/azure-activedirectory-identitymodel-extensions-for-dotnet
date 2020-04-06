﻿using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.ServiceModel.Federation.Tests.Mocks;
using System.ServiceModel.Security;
using System.Threading;
using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.XmlEnc;
using Xunit;
using SecurityToken = System.IdentityModel.Tokens.SecurityToken;
using SymmetricSecurityKey = System.IdentityModel.Tokens.SymmetricSecurityKey;

namespace System.ServiceModel.Federation.Tests
{
    public class WSTrustChannelSecurityTokenProviderTests
    {
        private static byte[] TestEntropy1 { get; } = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        private static byte[] TestEntropy2 { get; } = new byte[] { 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };
        private static byte[] TestEntropy3 { get; } = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };
        private static byte[] TestEntropy4 { get; } = new byte[] { 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

        [Theory, MemberData(nameof(CachingSettingsFromClientCredentialsTheoryData))]
        public void CachingSettingsAreInheritedFromClientCredentials(WsTrustChannelSecurityTokenProviderCachingTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.CachingSettingsAreInheritedFromClientCredentials", theoryData);

            try
            {
                var credentials = new WsTrustChannelClientCredentials()
                {
                    CacheIssuedTokens = theoryData.CacheIssuedTokens,
                    IssuedTokenRenewalThresholdPercentage = theoryData.IssuedTokenRenewalThresholdPercentage,
                    MaxIssuedTokenCachingTime = theoryData.MaxIssuedTokenCachingTime
                };

                SecurityTokenRequirement tokenRequirements = WSTrustTestHelpers.CreateSecurityRequirement(new BasicHttpBinding());
                var tokenProvider = credentials.CreateSecurityTokenManager().CreateSecurityTokenProvider(tokenRequirements) as WSTrustChannelSecurityTokenProvider;

                theoryData.ExpectedException.ProcessNoException(context);
                if (tokenProvider.CacheIssuedTokens != theoryData.CacheIssuedTokens)
                {
                    context.AddDiff($"Expected CacheIssuedTokens: {theoryData.CacheIssuedTokens}; actual CacheIssuedTokens: {tokenProvider.CacheIssuedTokens}");
                }
                if (tokenProvider.MaxIssuedTokenCachingTime != theoryData.MaxIssuedTokenCachingTime)
                {
                    context.AddDiff($"Expected MaxIssuedTokenCachingTime: {theoryData.MaxIssuedTokenCachingTime}; actual MaxIssuedTokenCachingTime: {tokenProvider.MaxIssuedTokenCachingTime}");
                }
                if (tokenProvider.IssuedTokenRenewalThresholdPercentage != theoryData.IssuedTokenRenewalThresholdPercentage)
                {
                    context.AddDiff($"Expected IssuedTokenRenewalThresholdPercentage: {theoryData.IssuedTokenRenewalThresholdPercentage}; actual IssuedTokenRenewalThresholdPercentage: {tokenProvider.IssuedTokenRenewalThresholdPercentage}");
                }
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustChannelSecurityTokenProviderCachingTheoryData> CachingSettingsFromClientCredentialsTheoryData
        {
            get => new TheoryData<WsTrustChannelSecurityTokenProviderCachingTheoryData>
            {
                new WsTrustChannelSecurityTokenProviderCachingTheoryData
                {
                    CacheIssuedTokens = false,
                    IssuedTokenRenewalThresholdPercentage = 80,
                    MaxIssuedTokenCachingTime = TimeSpan.FromDays(1)
                },
                new WsTrustChannelSecurityTokenProviderCachingTheoryData
                {
                    CacheIssuedTokens = true,
                    IssuedTokenRenewalThresholdPercentage = 100,
                    MaxIssuedTokenCachingTime = TimeSpan.MaxValue
                },
                new WsTrustChannelSecurityTokenProviderCachingTheoryData
                {
                    CacheIssuedTokens = false,
                    IssuedTokenRenewalThresholdPercentage = 0,
                    MaxIssuedTokenCachingTime = TimeSpan.FromDays(1),
                    ExpectedException = ExpectedException.ArgumentOutOfRangeException("value")
                },
                new WsTrustChannelSecurityTokenProviderCachingTheoryData
                {
                    CacheIssuedTokens = false,
                    IssuedTokenRenewalThresholdPercentage = 10,
                    MaxIssuedTokenCachingTime = TimeSpan.FromDays(-1),
                    ExpectedException = ExpectedException.ArgumentOutOfRangeException("value")
                }
            };
        }

        [Theory, MemberData(nameof(ProviderCachingTheoryData))]
        public void ProviderCaching(ProviderCachingTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.ProviderCaching", theoryData);

            try
            {
                SecurityToken token1 = theoryData.Provider1.GetToken(TimeSpan.FromMinutes(1));
                Thread.Sleep(theoryData.WaitBetweenGetTokenCallsMS);
                SecurityToken token2 = theoryData.Provider2.GetToken(TimeSpan.FromMinutes(1));

                theoryData.ExpectedException.ProcessNoException(context);
                IdentityComparer.AreEqual(token1.Id.Equals(token2.Id), theoryData.ShouldShareToken, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ProviderCachingTheoryData> ProviderCachingTheoryData
        {
            get
            {
                var data = new TheoryData<ProviderCachingTheoryData>();
                SecurityTokenRequirement tokenRequirement = WSTrustTestHelpers.CreateSecurityRequirement(new BasicHttpBinding());

                // Simple positive case
                var provider1 = new WSTrustChannelSecurityTokenProviderWithMockChannelFactory(tokenRequirement);
                data.Add(new ProviderCachingTheoryData
                {
                    Provider1 = provider1,
                    Provider2 = provider1,
                    ShouldShareToken = true
                });

                // Simple negative case
                var provider2 = new WSTrustChannelSecurityTokenProviderWithMockChannelFactory(tokenRequirement);
                data.Add(new ProviderCachingTheoryData
                {
                    Provider1 = provider1,
                    Provider2 = provider2,
                    ShouldShareToken = false
                });

                // Confirm that caches can be shared if contexts are the same
                var provider3 = new WSTrustChannelSecurityTokenProviderWithMockChannelFactory(tokenRequirement, provider1.RequestContext)
                {
                    // Share cache and context
                    TestIssuedTokensCache = provider1.TestIssuedTokensCache
                };
                data.Add(new ProviderCachingTheoryData
                {
                    Provider1 = provider1,
                    Provider2 = provider3,
                    ShouldShareToken = true
                });

                // Confirm that different contexts will result in not re-using tokens
                var provider4 = new WSTrustChannelSecurityTokenProviderWithMockChannelFactory(tokenRequirement)
                {
                    // Share cache but not context
                    TestIssuedTokensCache = provider1.TestIssuedTokensCache
                };
                data.Add(new ProviderCachingTheoryData
                {
                    Provider1 = provider1,
                    Provider2 = provider4,
                    ShouldShareToken = false
                });

                // Confirm that no caching occurs when caching is disabled
                var provider5 = new WSTrustChannelSecurityTokenProviderWithMockChannelFactory(tokenRequirement)
                {
                    CacheIssuedTokens = false
                };
                data.Add(new ProviderCachingTheoryData
                {
                    Provider1 = provider5,
                    Provider2 = provider5,
                    ShouldShareToken = false
                });

                // Confirm that tokens are cached longer than MaxIssuedTokenCachingTime
                var provider6 = new WSTrustChannelSecurityTokenProviderWithMockChannelFactory(tokenRequirement)
                {
                    MaxIssuedTokenCachingTime = TimeSpan.FromSeconds(2)
                };
                data.Add(new ProviderCachingTheoryData
                {
                    Provider1 = provider6,
                    Provider2 = provider6,
                    WaitBetweenGetTokenCallsMS = 500,
                    ShouldShareToken = true
                });
                data.Add(new ProviderCachingTheoryData
                {
                    Provider1 = provider6,
                    Provider2 = provider6,
                    WaitBetweenGetTokenCallsMS = 2500,
                    ShouldShareToken = false
                });

                return data;
            }
        }

        [Theory, MemberData(nameof(ProofTokenTheoryData))]
        public void ProofTokenGeneration(ProofTokenGenerationTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.ProofToken", theoryData);

            try
            {
                SecurityTokenRequirement tokenRequirement = WSTrustTestHelpers.CreateSecurityRequirement(
                    new BasicHttpBinding(),
                    keyType: theoryData.RequestKeyType,
                    securityAlgorithmSuite: theoryData.RequestSecurityAlgorithmSuite);
                var provider = new WSTrustChannelSecurityTokenProviderWithMockChannelFactory(tokenRequirement)
                {
                    CacheIssuedTokens = false,
                    RequestEntropy = theoryData.RequestEntropy,
                    RequestKeySizeInBits = theoryData.RequestKeySize
                };
                provider.SetResponseSettings(theoryData.ResponseSettings);

                GenericXmlSecurityToken token = provider.GetToken(TimeSpan.FromMinutes(1)) as GenericXmlSecurityToken;

                theoryData.ExpectedException.ProcessNoException(context);

                if (theoryData.ExpectedProofKey is null)
                {
                    IdentityComparer.AreIntsEqual(token.SecurityKeys.Count, 0, context);
                }
                else
                {
                    if (IdentityComparer.AreIntsEqual(token.SecurityKeys.Count, 1, context))
                    {
                        var key = token.SecurityKeys[0] as SymmetricSecurityKey;
                        if (theoryData.ExpectedProofKey.Length > 0)
                        {
                            // If the proof key is knowable, confirm it is correct
                            IdentityComparer.AreBytesEqual(key.GetSymmetricKey(), theoryData.ExpectedProofKey, context);
                        }

                        // If there is a proof key, get a second token and make sure the proof key either
                        // changes or doesn't change depending on whether the entropy was specified explicitly or randomly generated.
                        GenericXmlSecurityToken token2 = provider.GetToken(TimeSpan.FromMinutes(1)) as GenericXmlSecurityToken;
                        var key2 = token2.SecurityKeys[0] as SymmetricSecurityKey;
                        var keyBytes = key.GetSymmetricKey();
                        var key2Bytes = key2.GetSymmetricKey();

                        if (IdentityComparer.AreIntsEqual(keyBytes.Length, key2Bytes.Length, context))
                        {
                            var identicalKeys = true;
                            for (var i = 0; i < keyBytes.Length; i++)
                            {
                                if (keyBytes[i] != key2Bytes[i])
                                {
                                    identicalKeys = false;
                                }
                            }

                            var expectedIdentical = theoryData.ExpectedProofKey.Length > 0;
                            if (identicalKeys && !expectedIdentical)
                            {
                                // Fail if the same key was returned twice when random entropy should be generated for each token
                                context.AddDiff("Two calls to WSTrustChannelSecurityTokenProvider without specific requestor entropy should have had different proof keys, but actually had the same proof keys");
                            }
                            if (!identicalKeys && expectedIdentical)
                            {
                                // Fail if different keys were returned when entropy was specified (which should have resulted in a deterministic key)
                                context.AddDiff("Two calls to WSTrustChannelSecurityTokenProvider with specific requestor entropy should have had identical proof keys, but actually had different proof keys");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ProofTokenGenerationTheoryData> ProofTokenTheoryData
        {
            get => new TheoryData<ProofTokenGenerationTheoryData>
            {
                new ProofTokenGenerationTheoryData
                {
                    // Default scenario
                    ExpectedProofKey = new byte[0], // Empty proof key means the proof key should be present but the value is unpredictable
                    TestId = "Symmetric, default entropy"
                },
                new ProofTokenGenerationTheoryData
                {
                    // Bearer token scenario
                    RequestEntropy = null,
                    RequestKeyType = SecurityKeyType.BearerKey,
                    ResponseSettings = new MockResponseSettings
                    {
                        Entropy = null,
                        ProofToken = null
                    },
                    ExpectedProofKey = null,
                    TestId = "Bearer"
                },
                new ProofTokenGenerationTheoryData
                {
                    // Client-supplied key material
                    RequestEntropy = new Entropy(new BinarySecret(TestEntropy1)),
                    ResponseSettings = new MockResponseSettings
                    {
                        Entropy = null,
                        ProofToken = null
                    },
                    ExpectedProofKey = TestEntropy1,
                    TestId = "Client-supplied key material, symmetric key"
                },
                new ProofTokenGenerationTheoryData
                {
                    // Client-supplied asymmetric key material
                    RequestEntropy = new Entropy(new BinarySecret(TestEntropy3)),
                    RequestKeyType = SecurityKeyType.AsymmetricKey,
                    ResponseSettings = new MockResponseSettings
                    {
                        Entropy = null,
                        ProofToken = null
                    },
                    ExpectedProofKey = TestEntropy3,
                    TestId = "Client-supplied key material, asymmetric key"
                },
                new ProofTokenGenerationTheoryData
                {
                    // Server-supplied key material
                    ResponseSettings = new MockResponseSettings
                    {
                        Entropy = null,
                        ProofToken = new RequestedProofToken(new BinarySecret(TestEntropy2))
                    },
                    ExpectedProofKey = TestEntropy2,
                    TestId = "Server-supplied key material"
                },
                new ProofTokenGenerationTheoryData
                {
                    // Computed key, default key size
                    RequestEntropy = new Entropy(new BinarySecret(TestEntropy2)),
                    ResponseSettings = new MockResponseSettings
                    {
                        Entropy = new Entropy(new BinarySecret(TestEntropy1)),
                        ProofToken = new RequestedProofToken(WsTrustKeyTypes.Trust13.PSHA1)
                    },
                    ExpectedProofKey = KeyGenerator.ComputeCombinedKey(TestEntropy1, TestEntropy2, 256),
                    TestId = "Computed key, default key size"
                },
                new ProofTokenGenerationTheoryData
                {
                    // Computed key, key size from response
                    RequestKeySize = 512,
                    RequestEntropy = new Entropy(new BinarySecret(TestEntropy3)),
                    ResponseSettings = new MockResponseSettings
                    {
                        Entropy = new Entropy(new BinarySecret(TestEntropy4)),
                        ProofToken = new RequestedProofToken(WsTrustKeyTypes.Trust13.PSHA1),
                        KeySizeInBits = 256
                    },
                    ExpectedProofKey = KeyGenerator.ComputeCombinedKey(TestEntropy4, TestEntropy3, 256),
                    TestId = "Computed key, key size from issuer"
                },
                new ProofTokenGenerationTheoryData
                {
                    // Computed key, key size from request
                    RequestKeySize = 1024,
                    RequestEntropy = new Entropy(new BinarySecret(TestEntropy1)),
                    ResponseSettings = new MockResponseSettings
                    {
                        Entropy = new Entropy(new BinarySecret(TestEntropy3)),
                        ProofToken = new RequestedProofToken(WsTrustKeyTypes.Trust13.PSHA1)
                    },
                    ExpectedProofKey = KeyGenerator.ComputeCombinedKey(TestEntropy3, TestEntropy1, 1024),
                    TestId = "Computed key, key size from requestor"
                },
                new ProofTokenGenerationTheoryData
                {
                    // Computed key, key size from non-default SecurityAlgorithmSuite
                    RequestSecurityAlgorithmSuite = SecurityAlgorithmSuite.TripleDes,
                    RequestEntropy = new Entropy(new BinarySecret(TestEntropy3)),
                    ResponseSettings = new MockResponseSettings
                    {
                        Entropy = new Entropy(new BinarySecret(TestEntropy1)),
                        ProofToken = new RequestedProofToken(WsTrustKeyTypes.Trust13.PSHA1)
                    },
                    ExpectedProofKey = KeyGenerator.ComputeCombinedKey(TestEntropy1, TestEntropy3, 192),
                    TestId = "Computed key, key size from non-default security algorithm suite"
                },
                new ProofTokenGenerationTheoryData
                {
                    // Throw if computed key and entropy are both present in response
                    RequestEntropy = null,
                    ResponseSettings = new MockResponseSettings
                    {
                        Entropy = new Entropy(new BinarySecret(TestEntropy1)),
                        ProofToken = new RequestedProofToken(new BinarySecret(TestEntropy1))
                    },
                    ExpectedException = new ExpectedException(typeof(InvalidOperationException)),
                    TestId = "Negative test: computed key algorithm and issuer entropy"
                },
                new ProofTokenGenerationTheoryData
                {
                    // Throw if computed key and proof token are both present in response
                    RequestEntropy = null,
                    ResponseSettings = new MockResponseSettings
                    {
                        ProofToken = new RequestedProofToken(new BinarySecret(TestEntropy1))
                        {
                            ComputedKeyAlgorithm = WsTrustKeyTypes.Trust13.PSHA1
                        }
                    },
                    ExpectedException = new ExpectedException(typeof(InvalidOperationException)),
                    TestId = "Negative test: computed key algorithm and proof token"
                },
                new ProofTokenGenerationTheoryData
                {
                    // Throw if computed key with asymmetric token
                    RequestEntropy = new Entropy(new BinarySecret(TestEntropy2)),
                    RequestKeyType = SecurityKeyType.AsymmetricKey,
                    ResponseSettings = new MockResponseSettings
                    {
                        Entropy = new Entropy(new BinarySecret(TestEntropy1)),
                        ProofToken = new RequestedProofToken(WsTrustKeyTypes.Trust13.PSHA1)
                    },
                    ExpectedException = new ExpectedException(typeof(InvalidOperationException)),
                    TestId = "Negative test: computed key with asymmetric key type"
                },
                new ProofTokenGenerationTheoryData
                {
                    // Throw for unsupported computed key algorithm
                    RequestEntropy = new Entropy(new BinarySecret(TestEntropy2)),
                    ResponseSettings = new MockResponseSettings
                    {
                        Entropy = new Entropy(new BinarySecret(TestEntropy1)),
                        ProofToken = new RequestedProofToken(WsTrustKeyTypes.Trust13.Symmetric)
                    },
                    ExpectedException = new ExpectedException(typeof(NotSupportedException)),
                    TestId = "Negative test: unsupported computed key algorithm"
                },
                new ProofTokenGenerationTheoryData
                {
                    // Throw for bearer with server entropy
                    RequestKeyType = SecurityKeyType.BearerKey,
                    ResponseSettings = new MockResponseSettings
                    {
                        Entropy = new Entropy(new BinarySecret(TestEntropy1)),
                        ProofToken = null
                    },
                    ExpectedException = new ExpectedException(typeof(InvalidOperationException)),
                    TestId = "Negative test: bearer key type with server entropy"
                },
                new ProofTokenGenerationTheoryData
                {
                    // Throw for bearer with proof token
                    RequestKeyType = SecurityKeyType.BearerKey,
                    ResponseSettings = new MockResponseSettings
                    {
                        Entropy = null,
                        ProofToken = new RequestedProofToken(new BinarySecret(TestEntropy2))
                    },
                    ExpectedException = new ExpectedException(typeof(InvalidOperationException)),
                    TestId = "Negative test: bearer key type and proof token"
                },
                new ProofTokenGenerationTheoryData
                {
                    // Throw for missing issuer entropy
                    RequestEntropy = new Entropy(new BinarySecret(TestEntropy2)),
                    ResponseSettings = new MockResponseSettings
                    {
                        ProofToken = new RequestedProofToken(WsTrustKeyTypes.Trust13.PSHA1)
                    },
                    ExpectedException = new ExpectedException(typeof(InvalidOperationException)),
                    TestId = "Negative test: computed key with no issuer entropy"
                },
                new ProofTokenGenerationTheoryData
                {
                    // Computed key with missing requestor entropy uses random entropy
                    ResponseSettings = new MockResponseSettings
                    {
                        Entropy = new Entropy(new BinarySecret(TestEntropy1)),
                        ProofToken = new RequestedProofToken(WsTrustKeyTypes.Trust13.PSHA1)
                    },
                    ExpectedProofKey = new byte[0], // Empty proof key means the proof key should be present but the value is unpredictable
                    TestId = "Computed key with default requestor entropy"
                },
                new ProofTokenGenerationTheoryData
                {
                    // Throw for incomplete issuer entropy
                    RequestEntropy = new Entropy(new BinarySecret(TestEntropy2)),
                    ResponseSettings = new MockResponseSettings
                    {
                        Entropy = new Entropy(new ProtectedKey(TestEntropy1, null)),
                        ProofToken = new RequestedProofToken(WsTrustKeyTypes.Trust13.PSHA1)
                    },
                    ExpectedException = new ExpectedException(typeof(InvalidOperationException)),
                    TestId = "Negative test: computed key with incomplete issuer entropy"
                },
                new ProofTokenGenerationTheoryData
                {
                    // Throw for incomplete requestor entropy
                    RequestEntropy = new Entropy(new ProtectedKey(TestEntropy1, null)),
                    ResponseSettings = new MockResponseSettings
                    {
                        Entropy = new Entropy(new BinarySecret(TestEntropy1)),
                        ProofToken = new RequestedProofToken(WsTrustKeyTypes.Trust13.PSHA1)
                    },
                    ExpectedException = new ExpectedException(typeof(InvalidOperationException)),
                    TestId = "Negative test: computed key with incomplete requestor entropy"
                }
            };
        }

        [Theory, MemberData(nameof(ErrorConditionTheoryData))]
        public void ExceptionsAreThrownForErrorConditions(ErrorConditionTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ExceptionsAreThrownForErrorConditions", theoryData);

            try
            {
                // Create provider
                SecurityTokenRequirement tokenRequirement = WSTrustTestHelpers.CreateSecurityRequirement(new BasicHttpBinding());
                var provider = new WSTrustChannelSecurityTokenProviderWithMockChannelFactory(tokenRequirement);

                theoryData.Action(provider);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ErrorConditionTheoryData> ErrorConditionTheoryData
        {
            get => new TheoryData<ErrorConditionTheoryData>
            {
                new ErrorConditionTheoryData
                {
                    Action = (WSTrustChannelSecurityTokenProvider p) => p.MaxIssuedTokenCachingTime = TimeSpan.Zero,
                    ExpectedException = ExpectedException.ArgumentOutOfRangeException("value"),
                    First = true
                },
                new ErrorConditionTheoryData
                {
                    Action = (WSTrustChannelSecurityTokenProvider p) => p.MaxIssuedTokenCachingTime = TimeSpan.FromSeconds(-1),
                    ExpectedException = ExpectedException.ArgumentOutOfRangeException("value")
                },
                new ErrorConditionTheoryData
                {
                    Action = (WSTrustChannelSecurityTokenProvider p) => p.IssuedTokenRenewalThresholdPercentage = 0,
                    ExpectedException = ExpectedException.ArgumentOutOfRangeException("value")
                },
                new ErrorConditionTheoryData
                {
                    Action = (WSTrustChannelSecurityTokenProvider p) => p.IssuedTokenRenewalThresholdPercentage = -1,
                    ExpectedException = ExpectedException.ArgumentOutOfRangeException("value")
                },
                new ErrorConditionTheoryData
                {
                    Action = (WSTrustChannelSecurityTokenProvider p) => p.IssuedTokenRenewalThresholdPercentage = 101,
                    ExpectedException = ExpectedException.ArgumentOutOfRangeException("value")
                },
                new ErrorConditionTheoryData
                {
                    Action = (WSTrustChannelSecurityTokenProvider p) => (p as WSTrustChannelSecurityTokenProviderWithMockChannelFactory).TestIssuedTokensCache = null,
                    ExpectedException = ExpectedException.ArgumentNullException("value")
                }
            };
        }
    }
}
