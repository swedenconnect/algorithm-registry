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
package se.swedenconnect.security.algorithms.curves;

import java.util.List;
import java.util.function.Predicate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An singleton for easy access to the {@link NamedCurveRegistry}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class NamedCurveRegistrySingleton implements NamedCurveRegistry {

  /** Logger. */
  private final static Logger log = LoggerFactory.getLogger(NamedCurveRegistrySingleton.class);

  /** The singleton instance. */
  private static final NamedCurveRegistrySingleton instance = new NamedCurveRegistrySingleton();

  /** The registry. */
  private NamedCurveRegistry registry;

  // Hidden constructor.
  private NamedCurveRegistrySingleton() {
  }

  /**
   * Gets the singleton instance.
   *
   * @return the singleton instance
   */
  public static NamedCurveRegistrySingleton getInstance() {
    return instance;
  }

  /**
   * Assigns the {@link NamedCurveRegistry} instance to be used by this singleton. If no instance is assigned, a default
   * implementation of the registry will be used.
   *
   * @param registry
   *          the registry to be used by the singleton
   */
  public static void setAlgorithmRegistry(final NamedCurveRegistry registry) {
    if (instance.registry != null) {
      throw new SecurityException(
        "Cannot assign named curve registry to NamedCurveRegistrySingleton - it has already been initialized");
    }
    instance.registry = registry;
  }

  /** {@inheritDoc} */
  @Override
  public NamedCurve getCurve(final String name) {
    return this.getNamedCurveRegistry().getCurve(name);
  }

  /** {@inheritDoc} */
  @Override
  public NamedCurve getCurve(final Predicate<NamedCurve> predicate) {
    return this.getNamedCurveRegistry().getCurve(predicate);
  }

  /** {@inheritDoc} */
  @Override
  public List<NamedCurve> getCurves(final Predicate<NamedCurve> predicate) {
    return this.getNamedCurveRegistry().getCurves(predicate);
  }

  /**
   * Gets the {@link NamedCurveRegistry} instance to use. If no instance has been configured a default implementation is
   * used ({@link StaticNamedCurveRegistry}).
   *
   * @return a NamedCurveRegistry
   */
  private NamedCurveRegistry getNamedCurveRegistry() {
    if (this.registry == null) {
      log.info("Registry not initialized - using default implementation ...");
      synchronized (this) {
        this.registry = new StaticNamedCurveRegistry();
      }
    }
    return registry;
  }

}
