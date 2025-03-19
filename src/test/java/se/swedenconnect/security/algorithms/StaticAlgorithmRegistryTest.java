/*
 * Copyright 2022-2025 Sweden Connect
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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import se.swedenconnect.security.algorithms.impl.StaticAlgorithmRegistry;

/**
 * Test cases for StaticAlgorithmRegistry.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class StaticAlgorithmRegistryTest {

  @Test
  public void testInstantiate() {
    final StaticAlgorithmRegistry registry = new StaticAlgorithmRegistry();
    Assertions.assertNotNull(registry);
  }

  @Test
  public void testAllPresent() {
    final StaticAlgorithmRegistry registry = new StaticAlgorithmRegistry();

    for (final Algorithm a : StaticAlgorithmRegistry.getDefaultDigestAlgorithms()) {
      final Algorithm algorithm = registry.getAlgorithm(a.getUri());
      Assertions.assertEquals(a, algorithm);
    }
    for (final Algorithm a : StaticAlgorithmRegistry.getDefaultSignatureAlgorithms()) {
      final Algorithm algorithm = registry.getAlgorithm(a.getUri());
      Assertions.assertEquals(a, algorithm);
    }
    for (final Algorithm a : StaticAlgorithmRegistry.getDefaultMacAlgorithms()) {
      final Algorithm algorithm = registry.getAlgorithm(a.getUri());
      Assertions.assertEquals(a, algorithm);
    }
    for (final Algorithm a : StaticAlgorithmRegistry.getDefaultSymmetricKeyWrapAlgorithms()) {
      final Algorithm algorithm = registry.getAlgorithm(a.getUri());
      Assertions.assertEquals(a, algorithm);
    }
    for (final Algorithm a : StaticAlgorithmRegistry.getDefaultBlockEncryptionAlgorithms()) {
      final Algorithm algorithm = registry.getAlgorithm(a.getUri());
      Assertions.assertEquals(a, algorithm);
    }
    for (final Algorithm a : StaticAlgorithmRegistry.getDefaultKeyTransportAlgorithms()) {
      final Algorithm algorithm = registry.getAlgorithm(a.getUri());
      Assertions.assertEquals(a, algorithm);
    }

  }

}
