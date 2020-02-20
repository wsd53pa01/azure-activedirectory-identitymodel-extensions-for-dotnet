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
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.WsFederation;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.Tests
{
    /// <summary>
    /// 
    /// </summary>
    public class ExceptionTests
    {
        [Theory, MemberData(nameof(ExceptionSerializationTheoryData))]
        public void SerializationAndDeserializeExceptions(ExceptionTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.SerializeAndDeserializeExceptions", theoryData);
            try
            {
                Exception testException;
                using (Stream s = new MemoryStream())
                {
                    BinaryFormatter formatter = new BinaryFormatter();
                    formatter.Serialize(s, theoryData.Exception);
                    s.Position = 0; // Reset stream position
                    testException = (Exception)formatter.Deserialize(s);
                }

                IdentityComparer.AreEqual(theoryData.Exception, testException, context);
            }
            catch (Exception exception)
            {
                theoryData.ExpectedException.ProcessException(exception);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ExceptionTheoryData> ExceptionSerializationTheoryData()
        {
            var theoryData = new TheoryData<ExceptionTheoryData>();
            AddOpenIdConnectExceptions(theoryData);
            AddWsFederationExceptions(theoryData);
            return theoryData;
        }

        private static void AddOpenIdConnectExceptions(TheoryData<ExceptionTheoryData> theoryData)
        {
            theoryData.Add(new ExceptionTheoryData
            {
                TestId = nameof(OpenIdConnectProtocolException),
                Exception = new OpenIdConnectProtocolException("OpenIdConnectProtocolException")
            });

            theoryData.Add(new ExceptionTheoryData
            {
                TestId = nameof(OpenIdConnectProtocolInvalidAtHashException),
                Exception = new OpenIdConnectProtocolInvalidAtHashException("OpenIdConnectProtocolInvalidAtHashException")
            });

            theoryData.Add(new ExceptionTheoryData
            {
                TestId = nameof(OpenIdConnectProtocolInvalidCHashException),
                Exception = new OpenIdConnectProtocolInvalidCHashException("OpenIdConnectProtocolInvalidCHashException")
            });

            theoryData.Add(new ExceptionTheoryData
            {
                TestId = nameof(OpenIdConnectProtocolInvalidNonceException),
                Exception = new OpenIdConnectProtocolInvalidNonceException("OpenIdConnectProtocolInvalidNonceException")
            });

            theoryData.Add(new ExceptionTheoryData
            {
                TestId = nameof(OpenIdConnectProtocolInvalidStateException),
                Exception = new OpenIdConnectProtocolInvalidStateException("OpenIdConnectProtocolInvalidStateException")
            });
        }

        private static void AddWsFederationExceptions(TheoryData<ExceptionTheoryData> theoryData)
        {
            theoryData.Add(new ExceptionTheoryData
            {
                TestId = nameof(WsFederationException),
                Exception = new WsFederationException("WsFederationException")
            });

            theoryData.Add(new ExceptionTheoryData
            {
                TestId = nameof(WsFederationReadException),
                Exception = new WsFederationReadException("WsFederationReadException")
            });
        }

        public class ExceptionTheoryData : TheoryDataBase
        {
            public Exception Exception { get; set; }
           
        }
    }
}
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant

