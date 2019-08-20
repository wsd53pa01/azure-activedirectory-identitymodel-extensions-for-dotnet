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

namespace Microsoft.IdentityModel.JsonWebTokens
{
    /// <summary>
    /// The claim names used when looking up registered header claims during token validation/creation.
    /// <see cref="JwtHeaderParameterNames"/> are used by default, but each instance of the <see cref="JsonWebTokenHandler"/>
    /// has its own instance of this class, which allows claim names to be overridden if necessary.
    /// </summary>
    public class CustomJwtHeaderParameterNames
    {
        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.1
        /// </summary>
        public string Alg = JwtHeaderParameterNames.Alg;

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.10
        /// also:https://tools.ietf.org/html/rfc7519#section-5.2
        /// </summary>
        public string Cty = JwtHeaderParameterNames.Cty;

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7516#section-4.1.2
        /// </summary>
        public string Enc = JwtHeaderParameterNames.Enc;

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7518#section-4.7.1.1
        /// </summary>
        public string IV = JwtHeaderParameterNames.IV;

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.2
        /// </summary>
        public string Jku = JwtHeaderParameterNames.Jku;

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.3
        /// </summary>
        public string Jwk = JwtHeaderParameterNames.Jwk;

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.4
        /// </summary>
        public string Kid = JwtHeaderParameterNames.Kid;

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.9
        /// also:https://tools.ietf.org/html/rfc7519#section-5.1
        /// </summary>
        public string Typ = JwtHeaderParameterNames.Typ;

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.6
        /// </summary>
        public string X5c = JwtHeaderParameterNames.X5c;

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#page-12
        /// </summary>
        public string X5t = JwtHeaderParameterNames.X5t;

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.5
        /// </summary>
        public string X5u = JwtHeaderParameterNames.X5u;

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7516#section-4.1.3
        /// </summary>
        public string Zip = JwtHeaderParameterNames.Zip;
    }
}
