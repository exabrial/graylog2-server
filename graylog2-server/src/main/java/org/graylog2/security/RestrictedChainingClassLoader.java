/**
 * This file is part of Graylog.
 *
 * Graylog is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Graylog is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Graylog.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.graylog2.security;

import org.graylog2.shared.plugins.ChainingClassLoader;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.util.Locale;

/**
 * A wrapper around the chaining class loader that only loads classes whose fully qualified name starts with an
 * allowed prefix. Prevents arbitrary class instantiation via the cluster config REST API.
 * Backport of upstream fix for CVE-2024-24824 (GHSA-p6gg-5hf4-4rgj).
 */
@Singleton
public class RestrictedChainingClassLoader {
    private final ChainingClassLoader delegate;
    private final SafeClasses safeClasses;

    @Inject
    public RestrictedChainingClassLoader(ChainingClassLoader delegate) {
        this.delegate = delegate;
        this.safeClasses = SafeClasses.allGraylogInternal();
    }

    public Class<?> loadClassSafely(String name) throws ClassNotFoundException, UnsafeClassLoadingAttemptException {
        if (safeClasses.isSafeToLoad(name)) {
            return delegate.loadClass(name);
        } else {
            throw new UnsafeClassLoadingAttemptException(
                    String.format(Locale.ROOT, "Prevented loading of unsafe class \"%s\". Only classes with prefixes " +
                            "[org.graylog., org.graylog2.] are allowed.", name)
            );
        }
    }
}
