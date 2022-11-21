package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes;

import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.StampedLock;

import org.palladiosimulator.pcm.core.entity.Entity;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ModifyEntity;

public class ChangesStorage<T extends ModifyEntity<E>, E extends Entity> {

    private StampedLock lock = new StampedLock();

    private Map<String, T> elements;

    public boolean insertElement(T element) {
        var stamp = this.lock.writeLock();
        try {
            return this.elements.putIfAbsent(element.getAffectedElement().getId(), element) == null;
        }finally {
            this.lock.unlockWrite(stamp);
        }
    }

    public boolean contains(E element) {
        var stamp = this.lock.readLock();
        try {
            return this.elements.containsKey(element.getId());
        }finally{
            this.lock.unlockRead(stamp);
        }
    }

    public List<E> get() {
        var stamp = this.lock.readLock();
        try {
            return this.elements.values().stream().map(ModifyEntity::getAffectedElement).toList();
        } finally {
            this.lock.unlockRead(stamp);
        }

    }




}
