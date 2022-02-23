/*
 * Copyright 2022 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.swedenconnect.security.algorithms.impl;

import java.security.Security;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.Requirement;

import se.swedenconnect.security.algorithms.Algorithm;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;

/**
 * Static implementation of the {@link AlgorithmRegistry} with fixed defaults.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class StaticAlgorithmRegistry extends AlgorithmRegistryImpl {

  /** Logger. */
  private final static Logger log = LoggerFactory.getLogger(StaticAlgorithmRegistry.class);

  /**
   * Default constructor.
   */
  public StaticAlgorithmRegistry() {
    super();

    // We need the Bouncy Castle provider ...
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      log.info("Crypto provider '{}' is not installed, installing it ...", BouncyCastleProvider.PROVIDER_NAME);
      Security.addProvider(new BouncyCastleProvider());
      log.info("Crypto provider '{}' was installed", BouncyCastleProvider.PROVIDER_NAME);
    }

    // Register
    Arrays.stream(getDefaultDigestAlgorithms()).forEach(a -> this.register(a));
    Arrays.stream(getDefaultSignatureAlgorithms()).forEach(a -> this.register(a));
    Arrays.stream(getDefaultMacAlgorithms()).forEach(a -> this.register(a));
    Arrays.stream(getDefaultSymmetricKeyWrapAlgorithms()).forEach(a -> this.register(a));
    Arrays.stream(getDefaultBlockEncryptionAlgorithms()).forEach(a -> this.register(a));
    Arrays.stream(getDefaultKeyTransportAlgorithms()).forEach(a -> this.register(a));
  }

  /**
   * Gets an array of the digest algorithms that the static algorithm registry supports.
   *
   * @return an array of algorithms
   */
  public static Algorithm[] getDefaultDigestAlgorithms() {
    if (defaultDigestAlgorithms == null) {
      defaultDigestAlgorithms = new Algorithm[] {
          MessageDigestAlgorithmImpl.builder(MessageDigestAlgorithm.ALGO_ID_DIGEST_NOT_RECOMMENDED_MD5)
            .jcaName("MD5")
            .blacklisted(true)
            .build(),
          MessageDigestAlgorithmImpl.builder(MessageDigestAlgorithm.ALGO_ID_DIGEST_RIPEMD160)
            .jcaName("RIPEMD160")
            .build(),
          MessageDigestAlgorithmImpl.builder(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1)
            .jcaName("SHA-1")
            .blacklisted(true)
            .build(),
          MessageDigestAlgorithmImpl.builder(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA224)
            .jcaName("SHA-224")
            .build(),
          MessageDigestAlgorithmImpl.builder(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256)
            .jcaName("SHA-256")
            .build(),
          MessageDigestAlgorithmImpl.builder(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA384)
            .jcaName("SHA-384")
            .build(),
          MessageDigestAlgorithmImpl.builder(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512)
            .jcaName("SHA-512")
            .build(),
          MessageDigestAlgorithmImpl.builder(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA3_224)
            .jcaName("SHA3-224")
            .build(),
          MessageDigestAlgorithmImpl.builder(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA3_256)
            .jcaName("SHA3-256")
            .build(),
          MessageDigestAlgorithmImpl.builder(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA3_384)
            .jcaName("SHA3-384")
            .build(),
          MessageDigestAlgorithmImpl.builder(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA3_512)
            .jcaName("SHA3-512")
            .build()
      };
    }
    return defaultDigestAlgorithms;
  }

  /**
   * Gets an array of the signature algorithms that the static algorithm registry supports.
   *
   * @return an array of algorithms
   */
  public static Algorithm[] getDefaultSignatureAlgorithms() {
    if (defaultSignatureAlgorithms == null) {
      // Make sure we have the digest algorithms cache set ...
      getDefaultDigestAlgorithms();

      defaultSignatureAlgorithms = new Algorithm[] {
          SignatureAlgorithmImpl.builder(XMLSignature.ALGO_ID_SIGNATURE_DSA)
            .keyType("DSA")
            .jcaName("SHA1withDSA")
            .joseAlgorithm(null)
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1, defaultDigestAlgorithms))
            .blacklisted(true)
            .build(),
          SignatureAlgorithmImpl.builder(XMLSignature.ALGO_ID_SIGNATURE_DSA_SHA256)
            .keyType("DSA")
            .jcaName("SHA256withDSA")
            .joseAlgorithm(null)
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256, defaultDigestAlgorithms))
            .build(),
          SignatureAlgorithmImpl.builder(XMLSignature.ALGO_ID_SIGNATURE_NOT_RECOMMENDED_RSA_MD5)
            .keyType("RSA")
            .jcaName("MD5withRSA")
            .joseAlgorithm(null)
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_NOT_RECOMMENDED_MD5, defaultDigestAlgorithms))
            .blacklisted(true)
            .build(),
          SignatureAlgorithmImpl.builder(XMLSignature.ALGO_ID_SIGNATURE_RSA_RIPEMD160)
            .keyType("RSA")
            .jcaName("RIPEMD160withRSA")
            .joseAlgorithm(null)
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_RIPEMD160, defaultDigestAlgorithms))
            .build(),
          SignatureAlgorithmImpl.builder(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1)
            .keyType("RSA")
            .jcaName("SHA1withRSA")
            .joseAlgorithm(null)
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1, defaultDigestAlgorithms))
            .blacklisted(true)
            .build(),
          SignatureAlgorithmImpl.builder(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA224)
            .keyType("RSA")
            .jcaName("SHA224withRSA")
            .joseAlgorithm(null)
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA224, defaultDigestAlgorithms))
            .build(),
          SignatureAlgorithmImpl.builder(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256)
            .keyType("RSA")
            .jcaName("SHA256withRSA")
            .joseAlgorithm(JWSAlgorithm.RS256)
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256, defaultDigestAlgorithms))
            .build(),
          SignatureAlgorithmImpl.builder(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384)
            .keyType("RSA")
            .jcaName("SHA384withRSA")
            .joseAlgorithm(JWSAlgorithm.RS384)
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA384, defaultDigestAlgorithms))
            .build(),
          SignatureAlgorithmImpl.builder(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512)
            .keyType("RSA")
            .jcaName("SHA512withRSA")
            .joseAlgorithm(JWSAlgorithm.RS512)
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512, defaultDigestAlgorithms))
            .build(),
          RSAPSSSignatureAlgorithmImpl.getBuilder(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1_MGF1)
            .keyType("RSA")
            .jcaName("SHA1withRSAandMGF1")
            .parameterSpec(new PSSParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, 20, PSSParameterSpec.TRAILER_FIELD_BC))
            .joseAlgorithm(null)
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1, defaultDigestAlgorithms))
            .blacklisted(true)
            .build(),
          RSAPSSSignatureAlgorithmImpl.getBuilder(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA224_MGF1)
            .keyType("RSA")
            .jcaName("SHA224withRSAandMGF1")
            .parameterSpec(new PSSParameterSpec("SHA-224", "MGF1", MGF1ParameterSpec.SHA224, 28, PSSParameterSpec.TRAILER_FIELD_BC))
            .joseAlgorithm(null)
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA224, defaultDigestAlgorithms))
            .build(),
          RSAPSSSignatureAlgorithmImpl.getBuilder(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1)
            .keyType("RSA")
            .jcaName("SHA256withRSAandMGF1")
            .parameterSpec(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, PSSParameterSpec.TRAILER_FIELD_BC))
            .joseAlgorithm(JWSAlgorithm.PS256)
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256, defaultDigestAlgorithms))
            .build(),
          RSAPSSSignatureAlgorithmImpl.getBuilder(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384_MGF1)
            .keyType("RSA")
            .jcaName("SHA384withRSAandMGF1")
            .parameterSpec(new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, PSSParameterSpec.TRAILER_FIELD_BC))
            .joseAlgorithm(JWSAlgorithm.PS384)
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA384, defaultDigestAlgorithms))
            .build(),
          RSAPSSSignatureAlgorithmImpl.getBuilder(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512_MGF1)
            .keyType("RSA")
            .jcaName("SHA512withRSAandMGF1")
            .parameterSpec(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, PSSParameterSpec.TRAILER_FIELD_BC))
            .joseAlgorithm(JWSAlgorithm.PS512)
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512, defaultDigestAlgorithms))
            .build(),
          RSAPSSSignatureAlgorithmImpl.getBuilder(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_224_MGF1)
            .keyType("RSA")
            .jcaName("SHA3-224withRSAandMGF1")
            .parameterSpec(
              new PSSParameterSpec("SHA3-224", "MGF1", new MGF1ParameterSpec("SHA3-224"), 28, PSSParameterSpec.TRAILER_FIELD_BC))
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA3_224, defaultDigestAlgorithms))
            .build(),
          RSAPSSSignatureAlgorithmImpl.getBuilder(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_256_MGF1)
            .keyType("RSA")
            .jcaName("SHA3-256withRSAandMGF1")
            .parameterSpec(
              new PSSParameterSpec("SHA3-256", "MGF1", new MGF1ParameterSpec("SHA3-256"), 32, PSSParameterSpec.TRAILER_FIELD_BC))
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA3_256, defaultDigestAlgorithms))
            .build(),
          RSAPSSSignatureAlgorithmImpl.getBuilder(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_384_MGF1)
            .keyType("RSA")
            .jcaName("SHA3-384withRSAandMGF1")
            .parameterSpec(
              new PSSParameterSpec("SHA3-384", "MGF1", new MGF1ParameterSpec("SHA3-384"), 48, PSSParameterSpec.TRAILER_FIELD_BC))
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA3_384, defaultDigestAlgorithms))
            .build(),
          RSAPSSSignatureAlgorithmImpl.getBuilder(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_512_MGF1)
            .keyType("RSA")
            .jcaName("SHA3-512withRSAandMGF1")
            .parameterSpec(
              new PSSParameterSpec("SHA3-512", "MGF1", new MGF1ParameterSpec("SHA3-512"), 64, PSSParameterSpec.TRAILER_FIELD_BC))
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA3_512, defaultDigestAlgorithms))
            .build(),
          new NoParamsRSAPSSSignatureAlgorithm(),
          SignatureAlgorithmImpl.builder(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA1)
            .keyType("EC")
            .jcaName("SHA1withECDSA")
            .joseAlgorithm(null)
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1, defaultDigestAlgorithms))
            .blacklisted(true)
            .build(),
          SignatureAlgorithmImpl.builder(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA224)
            .keyType("EC")
            .jcaName("SHA224withECDSA")
            .joseAlgorithm(null)
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA224, defaultDigestAlgorithms))
            .build(),
          SignatureAlgorithmImpl.builder(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256)
            .keyType("EC")
            .jcaName("SHA256withECDSA")
            .joseAlgorithm(JWSAlgorithm.ES256)
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256, defaultDigestAlgorithms))
            .build(),
          SignatureAlgorithmImpl.builder(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA384)
            .keyType("EC")
            .jcaName("SHA384withECDSA")
            .joseAlgorithm(JWSAlgorithm.ES384)
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA384, defaultDigestAlgorithms))
            .build(),
          SignatureAlgorithmImpl.builder(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA512)
            .keyType("EC")
            .jcaName("SHA512withECDSA")
            .joseAlgorithm(JWSAlgorithm.ES512)
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512, defaultDigestAlgorithms))
            .build(),
          SignatureAlgorithmImpl.builder(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_RIPEMD160)
            .keyType("EC")
            .jcaName("RIPEMD160withECDSA")
            .joseAlgorithm(null)
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_RIPEMD160, defaultDigestAlgorithms))
            .build()
      };
    }
    return defaultSignatureAlgorithms;
  }

  /**
   * Gets an array of the MAC algorithms that the static algorithm registry supports.
   *
   * @return an array of algorithms
   */
  public static Algorithm[] getDefaultMacAlgorithms() {
    if (defaultMacAlgorithms == null) {
      // Make sure the defaultDigestAlgorithms cache is set ...
      getDefaultDigestAlgorithms();

      defaultMacAlgorithms = new Algorithm[] {
          MacAlgorithmImpl.builder(XMLSignature.ALGO_ID_MAC_HMAC_NOT_RECOMMENDED_MD5)
            .jcaName("HmacMD5")
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_NOT_RECOMMENDED_MD5, defaultDigestAlgorithms))
            .blacklisted(true)
            .build(),
          MacAlgorithmImpl.builder(XMLSignature.ALGO_ID_MAC_HMAC_RIPEMD160)
            .jcaName("HMACRIPEMD160")
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_RIPEMD160, defaultDigestAlgorithms))
            .build(),
          MacAlgorithmImpl.builder(XMLSignature.ALGO_ID_MAC_HMAC_SHA1)
            .jcaName("HmacSHA1")
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1, defaultDigestAlgorithms))
            .blacklisted(true)
            .build(),
          MacAlgorithmImpl.builder(XMLSignature.ALGO_ID_MAC_HMAC_SHA224)
            .jcaName("HmacSHA224")
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA224, defaultDigestAlgorithms))
            .build(),
          MacAlgorithmImpl.builder(XMLSignature.ALGO_ID_MAC_HMAC_SHA256)
            .jcaName("HmacSHA256")
            .joseAlgorithm(JWSAlgorithm.HS256)
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256, defaultDigestAlgorithms))
            .build(),
          MacAlgorithmImpl.builder(XMLSignature.ALGO_ID_MAC_HMAC_SHA384)
            .jcaName("HmacSHA384")
            .joseAlgorithm(JWSAlgorithm.HS384)
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA384, defaultDigestAlgorithms))
            .build(),
          MacAlgorithmImpl.builder(XMLSignature.ALGO_ID_MAC_HMAC_SHA512)
            .jcaName("HmacSHA512")
            .joseAlgorithm(JWSAlgorithm.HS512)
            .messageDigestAlgorithm(getDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512, defaultDigestAlgorithms))
            .build()
      };
    }
    return defaultMacAlgorithms;
  }

  /**
   * Gets an array of the symmetric key wrap algorithms that the static algorithm registry supports.
   *
   * @return an array of algorithms
   */
  public static final Algorithm[] getDefaultSymmetricKeyWrapAlgorithms() {
    if (defaultSymmetricKeyWrapAlgorithms == null) {
      defaultSymmetricKeyWrapAlgorithms = new Algorithm[] {
          SymmetricKeyWrapImpl.builder(XMLCipher.TRIPLEDES_KeyWrap)
            .jcaName("DESedeWrap")
            .keyType("DESede")
            .keyLength(192)
            .build(),
          SymmetricKeyWrapImpl.builder(XMLCipher.AES_128_KeyWrap)
            .jcaName("AESWrap")
            .joseAlgorithm(JWEAlgorithm.A128KW)
            .keyType("AES")
            .keyLength(128)
            .build(),
          SymmetricKeyWrapImpl.builder(XMLCipher.AES_192_KeyWrap)
            .jcaName("AESWrap")
            .joseAlgorithm(JWEAlgorithm.A192KW)
            .keyType("AES")
            .keyLength(192)
            .build(),
          SymmetricKeyWrapImpl.builder(XMLCipher.AES_256_KeyWrap)
            .jcaName("AESWrap")
            .joseAlgorithm(JWEAlgorithm.A256KW)
            .keyType("AES")
            .keyLength(256)
            .build(),
          SymmetricKeyWrapImpl.builder(XMLCipher.CAMELLIA_128_KeyWrap)
            .jcaName("CamelliaWrap")
            .keyType("Camellia")
            .keyLength(128)
            .build(),
          SymmetricKeyWrapImpl.builder(XMLCipher.CAMELLIA_192_KeyWrap)
            .jcaName("CamelliaWrap")
            .keyType("Camellia")
            .keyLength(192)
            .build(),
          SymmetricKeyWrapImpl.builder(XMLCipher.CAMELLIA_256_KeyWrap)
            .jcaName("CamelliaWrap")
            .keyType("Camellia")
            .keyLength(256)
            .build(),
          SymmetricKeyWrapImpl.builder(XMLCipher.SEED_128_KeyWrap)
            .jcaName("SEEDWrap")
            .keyType("SEED")
            .keyLength(128)
            .build()
      };
    }
    return defaultSymmetricKeyWrapAlgorithms;
  }

  /**
   * Gets an array of the block encryption algorithms that the static algorithm registry supports.
   *
   * @return an array of algorithms
   */
  public static Algorithm[] getDefaultBlockEncryptionAlgorithms() {
    if (defaultBlockEncryptionAlgorithms == null) {
      defaultBlockEncryptionAlgorithms = new Algorithm[] {
          BlockEncryptionAlgorithmImpl.builder(XMLCipher.TRIPLEDES)
            .jcaName("DESede/CBC/ISO10126Padding")
            .keyType("DESede")
            .keyLength(192)
            .ivLength(64)
            .build(),
          BlockEncryptionAlgorithmImpl.builder(XMLCipher.AES_128)
            .jcaName("AES/CBC/ISO10126Padding")
            .keyType("AES")
            .keyLength(128)
            .ivLength(128)
            .build(),
          BlockEncryptionAlgorithmImpl.builder(XMLCipher.AES_192)
            .jcaName("AES/CBC/ISO10126Padding")
            .keyType("AES")
            .keyLength(192)
            .ivLength(128)
            .build(),
          BlockEncryptionAlgorithmImpl.builder(XMLCipher.AES_256)
            .jcaName("AES/CBC/ISO10126Padding")
            .keyType("AES")
            .keyLength(256)
            .ivLength(128)
            .build(),
          BlockEncryptionAlgorithmImpl.builder(XMLCipher.AES_128_GCM)
            .jcaName("AES/GCM/NoPadding")
            .joseAlgorithm(EncryptionMethod.A128GCM)
            .keyType("AES")
            .keyLength(128)
            .ivLength(96)
            .build(),
          BlockEncryptionAlgorithmImpl.builder(XMLCipher.AES_192_GCM)
            .jcaName("AES/GCM/NoPadding")
            .joseAlgorithm(EncryptionMethod.A192GCM)
            .keyType("AES")
            .keyLength(192)
            .ivLength(96)
            .build(),
          BlockEncryptionAlgorithmImpl.builder(XMLCipher.AES_256_GCM)
            .jcaName("AES/GCM/NoPadding")
            .joseAlgorithm(EncryptionMethod.A256GCM)
            .keyType("AES")
            .keyLength(256)
            .ivLength(96)
            .build(),
          BlockEncryptionAlgorithmImpl.builder(XMLCipher.SEED_128)
            .jcaName("SEED/CBC/ISO10126Padding")
            .keyType("SEED")
            .keyLength(128)
            .ivLength(128)
            .build(),
          BlockEncryptionAlgorithmImpl.builder(XMLCipher.CAMELLIA_128)
            .jcaName("Camellia/CBC/ISO10126Padding")
            .keyType("Camellia")
            .keyLength(128)
            .ivLength(128)
            .build(),
          BlockEncryptionAlgorithmImpl.builder(XMLCipher.CAMELLIA_192)
            .jcaName("Camellia/CBC/ISO10126Padding")
            .keyType("Camellia")
            .keyLength(192)
            .ivLength(128)
            .build(),
          BlockEncryptionAlgorithmImpl.builder(XMLCipher.CAMELLIA_256)
            .jcaName("Camellia/CBC/ISO10126Padding")
            .keyType("Camellia")
            .keyLength(256)
            .ivLength(128)
            .build()
      };
    }
    return defaultBlockEncryptionAlgorithms;
  }

  /**
   * Gets an array of the key transport algorithms that the static algorithm registry supports.
   *
   * @return an array of algorithms
   */
  public static Algorithm[] getDefaultKeyTransportAlgorithms() {
    if (defaultKeyTransportAlgorithms == null) {
      defaultKeyTransportAlgorithms = new Algorithm[] {
          KeyTransportAlgorithmImpl.builder(XMLCipher.RSA_v1dot5)
            .jcaName("RSA/ECB/PKCS1Padding")
            .joseAlgorithm(new JWEAlgorithm("RSA1_5", Requirement.REQUIRED))
            .keyType("RSA")
            .blacklisted(true)
            .build(),
          KeyTransportAlgorithmImpl.builder(XMLCipher.RSA_OAEP_11)
            .jcaName("RSA/ECB/OAEPPadding")
            .joseAlgorithm(JWEAlgorithm.RSA_OAEP_256) // Not quite true
            .keyType("RSA")
            .build(),
          KeyTransportAlgorithmImpl.builder(XMLCipher.RSA_OAEP)
            .jcaName("RSA/ECB/OAEPPadding")
            .joseAlgorithm(new JWEAlgorithm("RSA-OAEP", Requirement.OPTIONAL))
            .keyType("RSA")
            .build()
      };
    }
    return defaultKeyTransportAlgorithms;
  }

  /** Cache for default digest algorithms. */
  private static Algorithm[] defaultDigestAlgorithms;

  /** Cache for default signature algorithms. */
  private static Algorithm[] defaultSignatureAlgorithms;

  /** Cache for default MAC algorithms. */
  private static Algorithm[] defaultMacAlgorithms;

  /** Cache for symmetric key wrap algorithms. */
  private static Algorithm[] defaultSymmetricKeyWrapAlgorithms;

  /** Cache for default block encryption algorithms. */
  private static Algorithm[] defaultBlockEncryptionAlgorithms;

  /** Cache for the default key transport algorithms. */
  private static Algorithm[] defaultKeyTransportAlgorithms;

  // Helper to use when creating signature algorithms
  private static se.swedenconnect.security.algorithms.MessageDigestAlgorithm getDigestAlgorithm(
      final String uri, final Algorithm[] algs) {
    return Arrays.stream(algs)
      .filter(d -> uri.equals(d.getUri()))
      .map(se.swedenconnect.security.algorithms.MessageDigestAlgorithm.class::cast)
      .findFirst()
      .orElse(null);
  }

}
