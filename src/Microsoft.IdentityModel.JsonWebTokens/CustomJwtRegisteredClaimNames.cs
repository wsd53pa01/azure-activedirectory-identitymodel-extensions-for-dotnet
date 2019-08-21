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
    /// The claim names used when looking up registered payload claims during token validation/creation.
    /// <see cref="JwtRegisteredClaimNames"/> are used by default, but each instance of the <see cref="JsonWebTokenHandler"/>
    /// has its own instance of this class, which allows claim names to be overridden if necessary.
    /// </summary>
    public class CustomJwtRegisteredClaimNames
    {
        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public string Actort = JwtRegisteredClaimNames.Actort;

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        /// </summary>
        public string Acr = JwtRegisteredClaimNames.Acr;

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        /// </summary>
        public string Amr = JwtRegisteredClaimNames.Amr;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public string Aud = JwtRegisteredClaimNames.Aud;

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        /// </summary>
        public string AuthTime = JwtRegisteredClaimNames.AuthTime;

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        /// </summary>
        public string Azp = JwtRegisteredClaimNames.Azp;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public string Birthdate = JwtRegisteredClaimNames.Birthdate;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public string CHash = JwtRegisteredClaimNames.CHash;

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
        /// </summary>
        public string AtHash = JwtRegisteredClaimNames.AtHash;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public string Email = JwtRegisteredClaimNames.Email;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public string Exp = JwtRegisteredClaimNames.Exp;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public string Gender = JwtRegisteredClaimNames.Gender;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public string FamilyName = JwtRegisteredClaimNames.FamilyName;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public string GivenName = JwtRegisteredClaimNames.GivenName;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public string Iat = JwtRegisteredClaimNames.Iat;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public string Iss = JwtRegisteredClaimNames.Iss;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public string Jti = JwtRegisteredClaimNames.Jti;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public string NameId = JwtRegisteredClaimNames.NameId;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public string Nonce = JwtRegisteredClaimNames.Nonce;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public string Nbf = JwtRegisteredClaimNames.Nbf;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public string Prn = JwtRegisteredClaimNames.Prn;

        /// <summary>
        /// http://openid.net/specs/openid-connect-frontchannel-1_0.html#OPLogout
        /// </summary>
        public string Sid = JwtRegisteredClaimNames.Sid;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public string Sub = JwtRegisteredClaimNames.Sub;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public string Typ = JwtRegisteredClaimNames.Typ;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public string UniqueName = JwtRegisteredClaimNames.UniqueName;

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public string Website = JwtRegisteredClaimNames.Website;
    }
}
