/*
 * Copyright 2022-2024 Sweden Connect
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
package se.swedenconnect.security.algorithms;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import se.swedenconnect.security.algorithms.impl.StaticAlgorithmRegistry;

import java.util.List;

/**
 * Test cases for AlgorithmPredicates.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class AlgorithmPredicatesTest {

  /** The registry we are testing against. */
  private final AlgorithmRegistry registry = new StaticAlgorithmRegistry();

  @Test
  public void testJcaName() {

    final Algorithm alg = this.registry.getAlgorithm(AlgorithmPredicates.fromJcaName("SHA-512"));
    Assertions.assertNotNull(alg);
    Assertions.assertTrue(alg instanceof MessageDigestAlgorithm);
    Assertions.assertEquals("SHA-512", alg.getJcaName());

    final MessageDigestAlgorithm malg =
        this.registry.getAlgorithm(AlgorithmPredicates.fromJcaName("SHA-512"), MessageDigestAlgorithm.class);
    Assertions.assertNotNull(malg);

    final List<MessageDigestAlgorithm> malgs =
        this.registry.getAlgorithms(AlgorithmPredicates.fromJcaName("SHA-512"), MessageDigestAlgorithm.class);
    Assertions.assertEquals(1, malgs.size());

    // Test when JCA name is not unique
    final EncryptionAlgorithm ealg =
        this.registry.getAlgorithm(AlgorithmPredicates.fromJcaName("AESWrap"), EncryptionAlgorithm.class);
    Assertions.assertNotNull(ealg);
    Assertions.assertEquals("AESWrap", ealg.getJcaName());

    final List<EncryptionAlgorithm> ealgs =
        this.registry.getAlgorithms(AlgorithmPredicates.fromJcaName("AESWrap"), EncryptionAlgorithm.class);
    Assertions.assertTrue(ealgs.size() > 1);
  }

  @Test
  public void testAlgorithmIdentifier() {
    final Algorithm alg = this.registry.getAlgorithm(
        AlgorithmPredicates.fromAlgorithmIdentifier(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)));
    Assertions.assertNotNull(alg);
    Assertions.assertEquals(NISTObjectIdentifiers.id_sha256,
        ((MessageDigestAlgorithm) alg).getAlgorithmIdentifier().getAlgorithm());
  }

}
