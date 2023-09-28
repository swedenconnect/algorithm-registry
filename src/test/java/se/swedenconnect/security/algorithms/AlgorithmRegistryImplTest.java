/*
 * Copyright 2022-2023 Sweden Connect
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

import java.util.Iterator;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Test cases for AlgorithmRegistryImpl.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class AlgorithmRegistryImplTest {

  private static AlgorithmRegistry registry = AlgorithmRegistrySingleton.getInstance();

  @Test
  public void testSorted() throws Exception {
    final List<SignatureAlgorithm> rsaAlgs =
        registry.getAlgorithms(AlgorithmPredicates.fromKeyType("RSA"), SignatureAlgorithm.class);

    // Assert that it is sorted with lowest entry first
    final SignatureAlgorithm first = rsaAlgs.get(0);
    final Iterator<SignatureAlgorithm> i = rsaAlgs.iterator();
    SignatureAlgorithm current, previous = i.next();
    while (i.hasNext()) {
      current = i.next();
      if (previous.getOrder() > current.getOrder()) {
        Assertions.fail("Not sorted by order");
      }
      previous = current;
    }

    // Assert that we get the lowest entry if we only ask for one.
    //
    final SignatureAlgorithm rsaAlg = registry.getAlgorithm(AlgorithmPredicates.fromKeyType("RSA"), SignatureAlgorithm.class);
    Assertions.assertEquals(first, rsaAlg);
  }

}
