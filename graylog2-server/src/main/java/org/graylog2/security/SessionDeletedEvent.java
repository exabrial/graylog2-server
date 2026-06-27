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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Cluster event fired when a session is deleted. Other nodes subscribe to this event
 * to clear the session from their local Shiro cache.
 * Backport of upstream fix for CVE-2023-41041 (GHSA-3fqm-frhg-7c85).
 */
public class SessionDeletedEvent {
    private final String sessionId;

    @JsonCreator
    public SessionDeletedEvent(@JsonProperty("session_id") String sessionId) {
        this.sessionId = sessionId;
    }

    @JsonProperty("session_id")
    public String sessionId() {
        return sessionId;
    }
}
