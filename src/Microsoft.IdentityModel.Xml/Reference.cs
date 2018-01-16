//----------7--------------------------------------------------------------------
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
using System.IO;
using System.Security.Cryptography;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using static Microsoft.IdentityModel.Logging.LogHelper;
using static Microsoft.IdentityModel.Xml.XmlUtil;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Represents a XmlDsig Reference element as per: https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-Reference
    /// </summary>
    public class Reference : DSigElement
    {
        private CanonicalizingTransfrom _canonicalizingTransfrom;
        private string _digestMethod;
        private string _digestValue;
        private XmlTokenStream _tokenStream;
        private TransformFactory _transformFactory = TransformFactory.Default;

        /// <summary>
        /// Initializes an instance of <see cref="Reference"/>
        /// </summary>
        public Reference()
        {
        }

        /// <summary>
        /// Initializes an instance of <see cref="Reference"/>.
        /// Gets or sets the CanonicalizingTransform
         /// </summary>
        /// <param name="transforms">an <see cref="IEnumerable{T}"/> of transforms to apply.</param>
        public Reference(IEnumerable<string> transforms)
        {
            if (transforms == null)
                throw LogArgumentNullException(nameof(transforms));

            foreach (var transform in transforms)
            {
                if (TransformFactory.IsSupportedTransform(transform))
                    Transforms.Add(TransformFactory.GetTransform(transform));
                else if (TransformFactory.IsSupportedCanonicalizingTransfrom(transform))
                    CanonicalizingTransfrom = TransformFactory.GetCanonicalizingTransform(transform);
                else
                    throw LogExceptionMessage(new NotSupportedException(FormatInvariant(LogMessages.IDX14210, transform)));
            }
        }

        /// <summary>
        /// Gets or sets the CanonicalizingTransform
        /// </summary>
        public CanonicalizingTransfrom CanonicalizingTransfrom
        {
            get => _canonicalizingTransfrom;
            set => _canonicalizingTransfrom = value ?? throw LogArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Gets or sets the DigestMethod to use when creating the hash.
        /// </summary>
        /// <exception cref="ArgumentNullException">if 'value' is null or empty.</exception>
        public string DigestMethod
        {
            get => _digestMethod;
            set => _digestMethod = (string.IsNullOrEmpty(value)) ? throw LogArgumentNullException(nameof(value)) : value;
        }

        /// <summary>
        /// Gets or sets the Base64 encoding of the hashed octets.
        /// </summary>
        /// <exception cref="ArgumentNullException">if 'value' is null or empty.</exception>
        public string DigestValue
        {
            get => _digestValue;
            set => _digestValue = (string.IsNullOrEmpty(value)) ? throw LogArgumentNullException(nameof(value)) : value;
        }

        /// <summary>
        /// Gets or sets the <see cref="XmlTokenStream"/> that is associated with the <see cref="DigestValue"/>.
        /// </summary>
        /// <exception cref="ArgumentNullException">if 'value' is null.</exception>
        public XmlTokenStream TokenStream
        {
            get => _tokenStream;
            set => _tokenStream = value ?? throw LogArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Gets or set the <see cref="TransformFactory"/> to use when processing references.
        /// </summary>
        /// <exception cref="ArgumentNullException">if 'value' is null.</exception>
        public TransformFactory TransformFactory
        {
            get => _transformFactory;
            set => _transformFactory = value ?? throw LogArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Gets the <see cref="IList{T}"/> of transforms to apply.
        /// </summary>
        public IList<Transform> Transforms
        {
            get;
        } = new List<Transform>();

        /// <summary>
        /// Gets or sets the Type of this Reference.
        /// </summary>
        public string Type
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the Uri of this Reference.
        /// </summary>
        public string Uri
        {
            get;
            set;
        }

        /// <summary>
        /// Verifies that the <see cref="DigestValue" /> equals the hashed value of the <see cref="TokenStream"/> after
        /// <see cref="Transforms"/> have been applied.
        /// </summary>
        /// <param name="cryptoProviderFactory">supplies the <see cref="HashAlgorithm"/>.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="cryptoProviderFactory"/> is null.</exception>
        public void Verify(CryptoProviderFactory cryptoProviderFactory)
        {
            if (cryptoProviderFactory == null)
                throw LogArgumentNullException(nameof(cryptoProviderFactory));

            if (!Utility.AreEqual(ComputeDigest(cryptoProviderFactory), Convert.FromBase64String(DigestValue)))
                throw LogValidationException(LogMessages.IDX30201, Uri ?? Id);
        }

        /// <summary>
        /// Writes into a stream and then hashes the bytes.
        /// </summary>
        /// <param name="tokenStream">the set of XML nodes to read.</param>
        /// <param name="hash">the hash algorithm to apply.</param>
        /// <returns>hash of the octets.</returns>
        private byte[] ProcessAndDigest(XmlTokenStream tokenStream, HashAlgorithm hash)
        {
            using (var stream = new MemoryStream())
            {
                using (var writer = XmlDictionaryWriter.CreateTextWriter(Stream.Null))
                {
                    tokenStream.WriteTo(writer);
                    writer.Flush();
                }

                stream.Flush();
                stream.Position = 0;
                return hash.ComputeHash(stream);
            }
        }

        /// <summary>
        /// Computes the digest of this reference by applying the transforms over the tokenStream.
        /// </summary>
        /// <param name="cryptoProviderFactory">the <see cref="CryptoProviderFactory"/> that will supply the <see cref="HashAlgorithm"/>.</param>
        /// <returns>The digest over the <see cref="TokenStream"/> after all transforms have been applied.</returns>
        /// <exception cref="ArgumentNullException">if <paramref name="cryptoProviderFactory"/> is null.</exception>
        /// <exception cref="XmlValidationException">if <see cref="TokenStream"/> is null.</exception>
        /// <exception cref="XmlValidationException">if <see cref="DigestMethod"/> is not supported.</exception>
        /// <exception cref="XmlValidationException">if <paramref name="cryptoProviderFactory"/>.CreateHashAlgorithm returns null.</exception>
        protected byte[] ComputeDigest(CryptoProviderFactory cryptoProviderFactory)
        {
            if (cryptoProviderFactory == null)
                throw LogArgumentNullException(nameof(cryptoProviderFactory));

            if (TokenStream == null)
                throw LogValidationException(LogMessages.IDX30202, Id);

            if (!cryptoProviderFactory.IsSupportedAlgorithm(DigestMethod))
                throw LogValidationException(LogMessages.IDX30208, cryptoProviderFactory.GetType(), DigestMethod);

            var hashAlg = cryptoProviderFactory.CreateHashAlgorithm(DigestMethod);
            if (hashAlg == null)
                throw LogValidationException(LogMessages.IDX30209, cryptoProviderFactory.GetType(), DigestMethod);

            try
            {
                // apply identity transform, just get the hash without any transforms
                if (Transforms.Count == 0)
                    return ProcessAndDigest(TokenStream, hashAlg);

                // specification requires last transform to be a canonicalizing transform
                // see: https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-ReferenceProcessingModel
                for (int i = 0;  i < Transforms.Count; i++)
                    TokenStream = Transforms[i].Process(TokenStream);

                return CanonicalizingTransfrom.ProcessAndDigest(TokenStream, hashAlg);
            }
            finally
            {
                if (hashAlg != null)
                    cryptoProviderFactory.ReleaseHashAlgorithm(hashAlg);
            }
        }
    }
}