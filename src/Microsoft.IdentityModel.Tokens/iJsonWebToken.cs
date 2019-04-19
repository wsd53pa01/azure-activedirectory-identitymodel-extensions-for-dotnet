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
    interface IJsonWebToken
    {
        /// <summary>
        /// Gets the 'value' of the 'actort' claim { actort, 'value' }.
        /// </summary>
        string Actor { get; set; }

        /// <summary>
        /// Gets the 'value' of the 'alg' claim { alg, 'value' }.
        /// </summary>
        string Alg { get; set; }

        /// <summary>
        /// Gets the list of 'aud' claim { aud, 'value' }.
        /// </summary>
        IEnumerable<string> Audiences { get; set; }

        /// <summary>
        /// Gets a <see cref="IEnumerable{Claim}"/><see cref="Claim"/> for each JSON { name, value }.
        /// </summary>
        IEnumerable<Claim> Claims { get; set; }

        /// <summary>
        /// Gets the 'value' of the 'cty' claim { cty, 'value' }.
        /// </summary>
        string Cty { get; set; }

        /// <summary>
        /// Gets the 'value' of the 'enc' claim { enc, 'value' }.
        /// </summary>
        string Enc { get; set; }

        /// <summary>
        /// Gets the 'value' of the 'jti' claim { jti, ''value' }.
        /// </summary>
        string Id { get; set; }

        /// <summary>
        /// Gets the 'value' of the 'iat' claim { iat, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        DateTime IssuedAt { get; set; }

        /// <summary>
        /// Gets the 'value' of the 'iss' claim { iss, 'value' }.
        /// </summary>
        string Issuer { get; set; }

        /// <summary>
        /// Gets the 'value' of the 'kid' claim { kid, 'value' }.
        /// </summary>
        string Kid { get; set; }

        /// <summary>
        /// Gets the <see cref="SecurityKey"/>s for this instance.
        /// </summary>
        SecurityKey SecurityKey { get; }

        /// <summary>
        /// Gets or sets the <see cref="SecurityKey"/> that signed this instance.
        /// </summary>
        SecurityKey SigningKey { get; set; }

        /// <summary>
        /// Gets the 'value' of the 'sub' claim { sub, 'value' }.
        /// </summary>
        string Subject { get; set; }

        /// <summary>
        /// Gets the 'value' of the 'typ' claim { typ, 'value' }.
        /// </summary>
        string Typ { get; set; }

        /// <summary>
        /// Gets the 'value' of the 'nbf' claim { nbf, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        DateTime ValidFrom { get; set; }

        /// <summary>
        /// Gets the 'value' of the 'exp' claim { exp, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        DateTime ValidTo { get; set; }

        /// <summary>
        /// Gets the 'value' of the 'x5t' claim { x5t, 'value' }.
        /// </summary>
        string X5t { get; set; }

        /// <summary>
        /// Gets the 'value' of the 'zip' claim { zip, 'value' }.
        /// </summary>
        string Zip { get; set; }

        /// <summary>
        /// Gets the 'value' corresponding to the provided key from the JWT payload { key, 'value' }.
        /// </summary>
        T GetPayloadValue<T>(string key);

        /// <summary>
        /// Tries to get the 'value' corresponding to the provided key from the JWT payload { key, 'value' }.
        /// </summary>
        bool TryGetPayloadValue<T>(string key, out T value);

        /// <summary>
        /// Gets the 'value' corresponding to the provided key from the JWT header { key, 'value' }.
        /// </summary>
        T GetHeaderValue<T>(string key);

        /// <summary>
        /// Tries to get the value corresponding to the provided key from the JWT header { key, 'value' }.
        /// </summary>
        bool TryGetHeaderValue<T>(string key, out T value);
    }
}
