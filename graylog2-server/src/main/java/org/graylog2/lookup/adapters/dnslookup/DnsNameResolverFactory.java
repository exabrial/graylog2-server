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
package org.graylog2.lookup.adapters.dnslookup;

import com.google.common.base.Splitter;
import com.google.common.net.HostAndPort;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.resolver.dns.DnsNameResolver;
import io.netty.resolver.dns.DnsNameResolverBuilder;
import io.netty.resolver.dns.DnsServerAddressStreamProvider;
import io.netty.resolver.dns.SequentialDnsServerAddressStreamProvider;
import org.apache.commons.collections4.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

/**
 * Factory for creating Netty {@link DnsNameResolver} instances.
 * Backport of upstream fix for CVE-2023-41045 (GHSA-g96c-x7rh-99r3).
 */
public class DnsNameResolverFactory {
    private static final Logger LOG = LoggerFactory.getLogger(DnsNameResolverFactory.class);
    private static final int DEFAULT_DNS_PORT = 53;

    private final NioEventLoopGroup eventLoopGroup;
    private final String dnsServerIps;
    private final long queryTimeout;

    public DnsNameResolverFactory(NioEventLoopGroup eventLoopGroup, String dnsServerIps, long queryTimeout) {
        this.eventLoopGroup = eventLoopGroup;
        this.dnsServerIps = dnsServerIps;
        this.queryTimeout = queryTimeout;
    }

    public DnsNameResolver create() {
        final List<InetSocketAddress> iNetDnsServerIps = parseServerIpAddresses(dnsServerIps);
        final DnsNameResolverBuilder dnsNameResolverBuilder = new DnsNameResolverBuilder(eventLoopGroup.next());
        dnsNameResolverBuilder.channelType(NioDatagramChannel.class).queryTimeoutMillis(queryTimeout);

        if (CollectionUtils.isNotEmpty(iNetDnsServerIps)) {
            LOG.debug("Attempting to start DNS client with server IPs [{}] on port [{}].",
                    dnsServerIps, DEFAULT_DNS_PORT);

            final DnsServerAddressStreamProvider dnsServer = new SequentialDnsServerAddressStreamProvider(iNetDnsServerIps);
            dnsNameResolverBuilder.nameServerProvider(dnsServer);
        } else {
            LOG.debug("Attempting to start DNS client with the local network adapter DNS server address on port [{}].",
                    DEFAULT_DNS_PORT);
        }

        return dnsNameResolverBuilder.build();
    }

    private List<InetSocketAddress> parseServerIpAddresses(String dnsServerIps) {
        return StreamSupport
                .stream(Splitter.on(",").trimResults().omitEmptyStrings().split(dnsServerIps).spliterator(), false)
                .map(hostAndPort -> HostAndPort.fromString(hostAndPort).withDefaultPort(DEFAULT_DNS_PORT))
                .map(hostAndPort -> new InetSocketAddress(hostAndPort.getHost(), hostAndPort.getPort()))
                .collect(Collectors.toList());
    }
}
