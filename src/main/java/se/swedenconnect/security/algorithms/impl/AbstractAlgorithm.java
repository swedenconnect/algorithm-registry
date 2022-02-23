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

import java.util.Objects;

import se.swedenconnect.security.algorithms.Algorithm;

/**
 * Abstract implementation of an {@link Algorithm}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class AbstractAlgorithm implements Algorithm {

  /** The algorithm URI. */
  private final String uri;

  /** The JCA name. */
  private String jcaName;

  /** Whether this algorithm is blacklisted. */
  private boolean blacklisted = false;

  /**
   * Constructor.
   * 
   * @param uri
   *          the algorithm URI
   * @param jcaName
   *          the JCA name
   */
  public AbstractAlgorithm(
      final String uri, final String jcaName) {
    this.uri = Objects.requireNonNull(uri, "The algorithm uri must be set");
    this.setJcaName(jcaName);
  }

  /**
   * Protected constructor used by builders.
   * 
   * @param uri
   *          the algorithm URI
   */
  protected AbstractAlgorithm(final String uri) {
    this.uri = Objects.requireNonNull(uri, "The algorithm uri must be set");
  }

  /** {@inheritDoc} */
  @Override
  public String getUri() {
    return this.uri;
  }

  /** {@inheritDoc} */
  @Override
  public String getJcaName() {
    return this.jcaName;
  }

  /**
   * Assigns the JCA name.
   * 
   * @param jcaName
   *          the JCA name
   */
  protected void setJcaName(final String jcaName) {
    this.jcaName = Objects.requireNonNull(jcaName, "The algorithm JCA name must be set");
  }

  /** {@inheritDoc} */
  @Override
  public boolean isBlacklisted() {
    return this.blacklisted;
  }

  /**
   * Sets whether this algorithm is blacklisted. The default is {@code false}.
   *
   * @param blacklisted
   *          whether this algorithm is blacklisted
   */
  public void setBlacklisted(final boolean blacklisted) {
    this.blacklisted = blacklisted;
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(this.blacklisted, this.jcaName, this.uri);
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof AbstractAlgorithm)) {
      return false;
    }
    final AbstractAlgorithm other = (AbstractAlgorithm) obj;
    return this.blacklisted == other.blacklisted && Objects.equals(this.jcaName, other.jcaName) 
        && Objects.equals(this.uri, other.uri);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format("uri='%s', jca-name='%s', blacklisted='%s'", this.uri, this.jcaName, this.blacklisted);
  }

  /**
   * Abstract builder for creating {@link Algorithm} objects.
   * 
   * @author Martin Lindström (martin@idsec.se)
   * @author Stefan Santesson (stefan@idsec.se)
   */
  protected abstract static class AbstractAlgorithmBuilder<T extends AbstractAlgorithm, B extends AlgorithmBuilder<T>>
      implements AlgorithmBuilder<T> {

    /** The algorithm being created. */
    private T algorithm;

    /**
     * Constructor.
     * 
     * @param algorithmUri
     *          the algorithm URI
     */
    public AbstractAlgorithmBuilder(final String algorithmUri) {
      this.algorithm = this.createAlgorithm(algorithmUri);
    }
    
    /** {@inheritDoc} */
    @Override
    public T build() {
      this.assertCorrect();
      return this.algorithm;
    }    

    /**
     * Assigns the JCA name.
     * 
     * @param jcaName
     *          the JCA name
     * @return the builder
     */
    public B jcaName(final String jcaName) {
      this.algorithm.setJcaName(jcaName);
      return this.getBuilder();
    }

    /**
     * Sets whether this algorithm is blacklisted. The default is {@code false}.
     *
     * @param blacklisted
     *          whether this algorithm is blacklisted
     * @return the builder
     */
    public B blacklisted(final boolean blacklisted) {
      this.algorithm.setBlacklisted(blacklisted);
      return this.getBuilder();
    }

    /**
     * Asserts that all fields have been assigned.
     * 
     * @throws IllegalArgumentException
     *           if a required field is missing
     */
    protected void assertCorrect() throws IllegalArgumentException {
      if (this.algorithm.getJcaName() == null) {
        throw new IllegalArgumentException("jcaName must be set");
      }
    }

    /**
     * Gets the current builder instance.
     * 
     * @return the builder instance
     */
    protected abstract B getBuilder();

    /**
     * Creates the {@link Algorithm} instance.
     * 
     * @param algorithmUri
     *          the algorithm URI
     * @return an Algorithm instance
     */
    protected abstract T createAlgorithm(final String algorithmUri);

    /**
     * Gets the algorithm instance that is being built.
     * 
     * @return the algorithm instance
     */
    protected final T getAlgorithm() {
      return this.algorithm;
    }
  }

}
