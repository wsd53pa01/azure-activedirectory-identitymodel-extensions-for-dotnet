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

namespace Microsoft.IdentityModel.Protocols.WsFederation
{
    /// <summary>
    /// Constants for WsTrust.
    /// </summary>
    public static class WsTrustConstants
    {
#pragma warning disable 1591

        /// <summary>
        /// The two different message types we can parse
        /// </summary>
        public static class Actions
        {
            public const string WsTrust13_Issue = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue";
            public const string WsTrust2005_Issue = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue";
        }

        /// <summary>
        /// Attributes that can be in a WsTrust message
        /// </summary>
        public static class Attributes
        {
            public const string EncodingType = "EncodingType";
            public const string EntityId = "entityID";
            public const string Id = "ID";
            public const string TokenType = "TokenType";
            public const string Type = "type";
            public const string Use = "use";
            public const string ValueType = "ValueType";
        }

        /// <summary>
        /// Elements that can be in a WsTrust message
        /// </summary>
        public static class Elements
        {
            public const string Address = "Address";
            public const string AppliesTo = "AppliesTo";
            public const string Created = "Created";
            public const string EndpointReference = "EndpointReference";
            public const string Expires = "Expires";
            public const string KeyIdentifier = "KeyIdentifier";
            public const string KeyType = "KeyType";
            public const string Lifetime = "Lifetime";
            public const string RequestedAttachedReference = "RequestedAttachedReference";
            public const string RequestedSecurityToken = "RequestedSecurityToken";
            public const string RequestSecurityTokenResponse = "RequestSecurityTokenResponse";
            public const string RequestType = "RequestType";
            public const string SecurityTokenReference = "SecurityTokenReference";
            public const string RequestedUnattachedReference = "RequestedUnattachedReference";
            public const string TokenType = "TokenType";
        }

        /// <summary>
        /// Namespaces that can be in a WsTrust message
        /// </summary>
        public static class Namespaces
        {
            public const string AddressingNamspace = "http://www.w3.org/2005/08/addressing";
            public const string FederationNamespace = "http://docs.oasis-open.org/wsfed/federation/200706";
            public const string MetadataNamespace = "urn:oasis:names:tc:SAML:2.0:metadata";
            public const string Utility = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
            public const string WsPolicy = "http://schemas.xmlsoap.org/ws/2004/09/policy";
            public const string WsTrust2005 = "http://schemas.xmlsoap.org/ws/2005/02/trust";
            public const string WsTrust1_3 = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
            public const string WsTrust1_4 = "http://docs.oasis-open.org/ws-sx/ws-trust/200802";
        }

        #pragma warning restore 1591
    }
}
 
