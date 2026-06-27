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

import com.google.common.collect.ImmutableSet;

import java.util.Set;

/**
 * Adds a safety net for class loading.
 * Backport of upstream fix for CVE-2024-24824 (GHSA-p6gg-5hf4-4rgj).
 */
public class SafeClasses {
    private static final Set<String> DEFAULT_PREFIXES = ImmutableSet.of("org.graylog.", "org.graylog2.");

    private final Set<String> prefixes;

    public SafeClasses(Set<String> prefixes) {
        this.prefixes = prefixes;
    }

    public static SafeClasses allGraylogInternal() {
        return new SafeClasses(DEFAULT_PREFIXES);
    }

    /**
     * Check if the class name is considered safe for loading by name from potentially user-provided input.
     * Classes are considered safe if their fully qualified class name starts with any of the configured prefixes.
     */
    public boolean isSafeToLoad(String className) {
        for (String prefix : prefixes) {
            if (className.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }
}
