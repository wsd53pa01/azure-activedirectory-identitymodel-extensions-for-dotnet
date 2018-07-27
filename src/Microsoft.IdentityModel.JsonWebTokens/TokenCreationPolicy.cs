//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;

namespace Microsoft.IdentityModel.JsonWebTokens
{
    /// <summary>
    /// Defines the policy to be used by the JsonWebTokenHandler when creating JsonWebTokens.
    /// </summary>
    public class TokenCreationPolicy
    {

        /// <summary>
        /// Gets or sets the 'expiration' time to be used when creating security tokens.
        /// </summary>
        public DateTime? Expires { get; set; }

        /// <summary>
        /// Represents the cryptographic operations that will be applied when creating JWT security tokens. 
        /// May optionally include additional properties of the security token to be created.
        /// </summary>
        public JObject Header { get; set; }

        /// <summary>
        /// Defines the inbound claim type mapping to be used when creating a security token.
        /// </summary>
        public IDictionary<string, string> InboundClaimTypeMap { get; set; }

        /// <summary>
        /// Gets or sets the 'issued at' time to be used when creating security tokens.
        /// </summary>
        public DateTime? IssuedAt { get; set; }

        /// <summary>
        /// Gets or sets the 'issuer' to be used when creating security tokens.
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// Gets or sets the 'not before' time to be used when creating security tokens.
        /// </summary>
        public DateTime? NotBefore { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="SigningCredentials"/> used to create security tokens.
        /// </summary>
        public SigningCredentials SigningCredentials { get; set; }

        /// <summary>
        /// Adds claims contained in this policy to the payload.
        /// </summary>
        /// <param name="payload">The payload to add claims to.</param>
        /// <returns></returns>
        public JObject AddClaims(JObject payload)
        {
            // Only add a claim value to the payload if it isn't null and if the payload doesn't
            // already have a value for that specific claim.
            if (Expires != null && payload[JwtRegisteredClaimNames.Exp] == null)
                payload.Add(JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(Expires.Value).ToString());
            if (IssuedAt != null && payload[JwtRegisteredClaimNames.Iat] == null)
                payload.Add(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(IssuedAt.Value).ToString());
            if (NotBefore != null && payload[JwtRegisteredClaimNames.Nbf] == null)
                payload.Add(JwtRegisteredClaimNames.Nbf, EpochTime.GetIntDate(NotBefore.Value).ToString());
            if (Issuer != null && payload[JwtRegisteredClaimNames.Iss] == null)
                payload.Add(JwtRegisteredClaimNames.Iss, Issuer);

            return payload;
        }
    }
}
