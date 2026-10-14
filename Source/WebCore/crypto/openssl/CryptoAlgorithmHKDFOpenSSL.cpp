/*
 * Copyright (C) 2020 Sony Interactive Entertainment Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "CryptoAlgorithmHKDF.h"

#include "CryptoAlgorithmHkdfParams.h"
#include "CryptoKeyRaw.h"
#include "OpenSSLUtilities.h"
#if defined(OPENSSL_IS_BORINGSSL)
#include <openssl/hkdf.h>
#else
#include <openssl/core_names.h>
#include <openssl/kdf.h>
#endif

namespace WebCore {

ExceptionOr<Vector<uint8_t>> CryptoAlgorithmHKDF::platformDeriveBits(const CryptoAlgorithmHkdfParams& parameters, const CryptoKeyRaw& key, size_t length, UseCryptoKit)
{
    auto algorithm = digestAlgorithm(parameters.hashIdentifier);
    if (!algorithm)
        return Exception { ExceptionCode::NotSupportedError };

    Vector<uint8_t> output(length / 8);
#if defined(OPENSSL_IS_BORINGSSL)
    if (HKDF(output.data(), output.size(), algorithm, key.key().data(), key.key().size(), parameters.saltVector().data(), parameters.saltVector().size(), parameters.infoVector().data(), parameters.infoVector().size()) <= 0)
        return Exception { ExceptionCode::OperationError };
#else
    // OpenSSL has no HKDF() one-shot (BoringSSL API); use the EVP_KDF interface (OpenSSL 3.0+).
    auto kdf = EVPKDFPtr(EVP_KDF_fetch(nullptr, OSSL_KDF_NAME_HKDF, nullptr));
    if (!kdf)
        return Exception { ExceptionCode::OperationError };
    auto ctx = EVPKDFCtxPtr(EVP_KDF_CTX_new(kdf.get()));
    if (!ctx)
        return Exception { ExceptionCode::OperationError };

    // OSSL_PARAM takes non-const buffers but only reads them here.
    const auto& keyData = key.key();
    const auto& salt = parameters.saltVector();
    const auto& info = parameters.infoVector();
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>(EVP_MD_get0_name(algorithm)), 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<uint8_t*>(keyData.data()), keyData.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<uint8_t*>(salt.data()), salt.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, const_cast<uint8_t*>(info.data()), info.size()),
        OSSL_PARAM_construct_end()
    };
    if (EVP_KDF_derive(ctx.get(), output.data(), output.size(), params) <= 0)
        return Exception { ExceptionCode::OperationError };
#endif

    return output;
}

} // namespace WebCore
