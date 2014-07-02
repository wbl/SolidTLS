/*
 * Copyright (c) 2014 Watson Ladd
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of the SolidTLS nor the names of its
 *  contributors may be used to endorse or promote products derived from
 *  this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

enum tls_ciphersuites {
  TLS_END_OF_LIST=0x0000,
  TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000A,
  TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F,
  TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035,
  TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003C,
  TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003D,
  TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xC008,
  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xC009,
  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xC00A,
  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xC013,
  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xC014,
  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC023,
  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xC024,
  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xC027,
  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xC028,
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B,
  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C,
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F,
  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030,
};
