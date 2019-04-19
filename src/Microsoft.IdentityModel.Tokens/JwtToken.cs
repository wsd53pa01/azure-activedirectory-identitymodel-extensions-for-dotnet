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

using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Base class for a JWT security token.
    /// </summary>
    public abstract class JwtToken : SecurityToken
    {
        /// <summary>
        /// Gets the 'value' of the 'actort' claim { actort, 'value' }.
        /// </summary>
        public abstract string Actor { get; }

        /// <summary>
        /// Gets the 'value' of the 'alg' claim { alg, 'value' }.
        /// </summary>
        public abstract string Alg { get; }

        /// <summary>
        /// Gets the list of 'aud' claim { aud, 'value' }.
        /// </summary>
        public abstract IEnumerable<string> Audiences { get; }

        /// <summary>
        /// Gets a <see cref="IEnumerable{Claim}"/><see cref="Claim"/> for each JSON { name, value }.
        /// </summary>
        public abstract IEnumerable<Claim> Claims { get; }

        /// <summary>
        /// Gets the 'value' of the 'cty' claim { cty, 'value' }.
        /// </summary>
        public abstract string Cty { get; }

        /// <summary>
        /// Gets the 'value' of the 'enc' claim { enc, 'value' }.
        /// </summary>
        public abstract string Enc { get; }

        /// <summary>
        /// Gets the 'value' of the 'iat' claim { iat, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        public abstract DateTime IssuedAt { get; }

        /// <summary>
        /// Gets the 'value' of the 'kid' claim { kid, 'value' }.
        /// </summary>
        public abstract string Kid { get; }

        /// <summary>
        /// Gets the 'value' of the 'sub' claim { sub, 'value' }.
        /// </summary>
        public abstract string Subject { get; }

        /// <summary>
        /// Gets the 'value' of the 'typ' claim { typ, 'value' }.
        /// </summary>
        public abstract string Typ { get; }

        /// <summary>
        /// Gets the 'value' of the 'x5t' claim { x5t, 'value' }.
        /// </summary>
        public abstract string X5t { get; }

        /// <summary>
        /// Gets the 'value' of the 'zip' claim { zip, 'value' }.
        /// </summary>
        public abstract string Zip { get; }

        /// <summary>
        /// Gets the 'value' corresponding to the provided key from the JWT payload { key, 'value' }.
        /// </summary>
        public abstract T GetPayloadValue<T>(string key);

        /// <summary>
        /// Tries to get the 'value' corresponding to the provided key from the JWT payload { key, 'value' }.
        /// </summary>
        public abstract bool TryGetPayloadValue<T>(string key, out T value);

        /// <summary>
        /// Gets the 'value' corresponding to the provided key from the JWT header { key, 'value' }.
        /// </summary>
        public abstract T GetHeaderValue<T>(string key);

        /// <summary>
        /// Tries to get the value corresponding to the provided key from the JWT header { key, 'value' }.
        /// </summary>
        public abstract bool TryGetHeaderValue<T>(string key, out T value);
    }
}
