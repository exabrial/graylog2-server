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

import com.google.common.util.concurrent.ThreadFactoryBuilder;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.resolver.dns.DnsNameResolver;
import io.netty.util.concurrent.Future;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

/**
 * Manages a pool of DNS resolvers with randomized source ports to prevent DNS cache poisoning.
 * Backport of upstream fix for CVE-2023-41045 (GHSA-g96c-x7rh-99r3).
 */
public class DnsResolverPool {
    private static final Logger LOG = LoggerFactory.getLogger(DnsResolverPool.class);
    private final long poolSize;
    private final long poolRefreshSeconds;
    private final ScheduledExecutorService executorService;
    private final NioEventLoopGroup eventLoopGroup;
    private final DnsNameResolverFactory resolverFactory;
    private final List<ResolverLease> resolverPool;

    protected DnsResolverPool(String dnsServerIps, long queryTimeout, long poolSize, long poolRefreshSeconds) {
        this.poolSize = poolSize;
        this.poolRefreshSeconds = poolRefreshSeconds;
        this.executorService = Executors.newSingleThreadScheduledExecutor(
                new ThreadFactoryBuilder().setNameFormat("dns-lookup-refresh-task-%d").build());
        this.resolverPool = Collections.synchronizedList(new ArrayList<ResolverLease>());
        this.eventLoopGroup = new NioEventLoopGroup();
        this.resolverFactory = new DnsNameResolverFactory(eventLoopGroup, dnsServerIps, queryTimeout);
    }

    protected void initialize() {
        for (int i = 0; i < poolSize; i++) {
            resolverPool.add(new ResolverLease(resolverFactory.create()));
        }
        executorService.scheduleAtFixedRate(new ResolverRefreshTask(), poolRefreshSeconds, poolRefreshSeconds, TimeUnit.SECONDS);
    }

    protected ResolverLease takeLease() {
        if (resolverPool.size() == 0) {
            throw new RuntimeException("Resolver pool is empty. Cannot return lease.");
        }
        final ResolverLease lease = resolverPool.get(randomResolverIndex());
        lease.take();
        return lease;
    }

    protected void returnLease(ResolverLease lease) {
        lease.release();
    }

    public void stop() {
        LOG.debug("Attempting to stop pool.");
        executorService.shutdown();
        if (resolverPool == null) {
            LOG.error("Resolver pool has not been initialized.");
            return;
        }
        synchronized (resolverPool) {
            final Iterator<ResolverLease> iterator = resolverPool.iterator();
            while (iterator.hasNext()) {
                final ResolverLease lease = iterator.next();
                if (lease.isLeased()) {
                    LOG.warn("Attempting to stop a leased resolver [{}].", lease.getId());
                }
                lease.take();
                lease.getResolver().close();
                iterator.remove();
            }
        }
        final Future<?> shutdownFuture = eventLoopGroup.shutdownGracefully();
        shutdownFuture.addListener(future -> LOG.debug("Finished shutting down pool."));
    }

    protected boolean isStopped() {
        return (eventLoopGroup == null || eventLoopGroup.isShutdown()) && executorService.isShutdown();
    }

    protected int randomResolverIndex() {
        return ThreadLocalRandom.current().nextInt(resolverPool.size());
    }

    private class ResolverRefreshTask implements Runnable {
        @Override
        public void run() {
            LOG.debug("Starting resolver refresh.");
            synchronized (resolverPool) {
                final ListIterator<ResolverLease> iterator = resolverPool.listIterator();
                while (iterator.hasNext()) {
                    final ResolverLease lease = iterator.next();
                    if (!lease.getHasBeenLeased()) {
                        continue;
                    }
                    if (!lease.isLeased()) {
                        lease.getResolver().close();
                        iterator.remove();
                        iterator.add(new ResolverLease(resolverFactory.create()));
                    } else {
                        LOG.warn("Lease for resolver [{}] is in-use. Skipping refresh.", lease.getId());
                    }
                }
            }
        }
    }

    protected static class ResolverLease {
        private final String id;
        private final DnsNameResolver resolver;
        private final AtomicInteger leaseCount;
        private final AtomicBoolean hasBeenLeased;

        private ResolverLease(DnsNameResolver resolver) {
            this.id = UUID.randomUUID().toString();
            this.resolver = resolver;
            this.leaseCount = new AtomicInteger(0);
            this.hasBeenLeased = new AtomicBoolean();
        }

        private void take() {
            this.leaseCount.incrementAndGet();
            this.hasBeenLeased.set(true);
        }

        private void release() {
            this.leaseCount.decrementAndGet();
        }

        protected String getId() {
            return id;
        }

        private boolean isLeased() {
            return leaseCount.get() > 0;
        }

        private boolean getHasBeenLeased() {
            return hasBeenLeased.get();
        }

        protected DnsNameResolver getResolver() {
            return resolver;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            final ResolverLease that = (ResolverLease) o;
            return Objects.equals(id, that.id);
        }

        @Override
        public int hashCode() {
            return Objects.hash(id);
        }
    }
}
