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

/**
 * Exception indicating an attempt to load a class that is not considered safe because its fully qualified class name
 * did not start with any of the allowed prefixes.
 * Backport of upstream fix for CVE-2024-24824 (GHSA-p6gg-5hf4-4rgj).
 */
public class UnsafeClassLoadingAttemptException extends Exception {
    public UnsafeClassLoadingAttemptException(String message) {
        super(message);
    }
}
