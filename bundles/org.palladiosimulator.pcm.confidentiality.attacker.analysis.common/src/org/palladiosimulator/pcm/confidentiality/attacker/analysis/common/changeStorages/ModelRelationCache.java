package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.changeStorages;

import java.util.HashMap;
import java.util.concurrent.locks.StampedLock;

public abstract class ModelRelationCache<T> {
    private final StampedLock lock = new StampedLock();

    private final HashMap<String, T> modelRelationMap;

    protected ModelRelationCache() {
        this.modelRelationMap = new HashMap<>();
    }

    public void reset() {
        final var stamp = this.lock.writeLock();
        try {
            this.modelRelationMap.clear();
        } finally {
            this.lock.unlockWrite(stamp);
        }
    }

    public void put(final String key, final T value) {
        final var stamp = this.lock.writeLock();
        try {
            this.modelRelationMap.computeIfAbsent(key, e -> value);
        } finally {
            this.lock.unlockWrite(stamp);
        }
    }

    public T get(final String key) {
        var stamp = this.lock.tryOptimisticRead();

        var value = this.modelRelationMap.get(key);
        if (!this.lock.validate(stamp)) {
            stamp = this.lock.readLock();
            try {
                value = this.modelRelationMap.get(key);
            } finally {
                this.lock.unlock(stamp);
            }
        }
        return value;
    }

    public boolean contains(final String key) {
        var stamp = this.lock.tryOptimisticRead();

        var value = this.modelRelationMap.containsKey(key);
        if (!this.lock.validate(stamp)) {
            stamp = this.lock.readLock();
            try {
                value = this.modelRelationMap.containsKey(key);
            } finally {
                this.lock.unlock(stamp);
            }
        }
        return value;
    }

}
