/*******************************************************************************
 * Copyright (c) 2026 RISE and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 *
 * Contributors:
 *     Rikard Höglund (RISE) - initial implementation
 *******************************************************************************/
package org.eclipse.leshan.server;

import java.util.HashMap;
import java.util.Map;

/**
 * A {@link HashMap} whose operations are synchronized.
 *
 * The EDHOC library requires {@link HashMap} instances for its credential maps, so a {@code ConcurrentHashMap} cannot
 * be passed. These maps are written by HTTP request threads (configs being pushed) while the EDHOC resource reads them
 * using CoAP threads; a plain HashMap could lose entries under concurrent writes.
 */
public class SynchronizedHashMap<K, V> extends HashMap<K, V> {

    private static final long serialVersionUID = 1L;

    @Override
    public synchronized V get(Object key) {
        return super.get(key);
    }

    @Override
    public synchronized V put(K key, V value) {
        return super.put(key, value);
    }

    @Override
    public synchronized boolean containsKey(Object key) {
        return super.containsKey(key);
    }

    @Override
    public synchronized boolean containsValue(Object value) {
        return super.containsValue(value);
    }

    @Override
    public synchronized V remove(Object key) {
        return super.remove(key);
    }

    @Override
    public synchronized void putAll(Map<? extends K, ? extends V> m) {
        super.putAll(m);
    }

    @Override
    public synchronized void clear() {
        super.clear();
    }

    @Override
    public synchronized int size() {
        return super.size();
    }

    @Override
    public synchronized boolean isEmpty() {
        return super.isEmpty();
    }
}
