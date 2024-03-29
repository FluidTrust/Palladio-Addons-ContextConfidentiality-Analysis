package edu.kit.ipd.sdq.kamp4attack.core;

import java.util.HashSet;
import java.util.Set;

import org.eclipse.emf.common.notify.Notification;
import org.eclipse.emf.common.notify.impl.AdapterImpl;
import org.palladiosimulator.pcm.core.entity.Entity;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ModifyEntity;

public class CacheCompromised {

    private final Set<String> compromised = new HashSet<>();

    private static CacheCompromised cache = new CacheCompromised();

    private CacheCompromised() {
        // TODO Auto-generated constructor stub
    }

    public boolean compromised(final Entity entity) {
        return entity.getId() != null ? this.compromised.contains(entity.getId()) : false;
    }

    public static CacheCompromised instance() {
        return cache;
    }

    public void reset() {
        this.compromised.clear();
    }

    public void register(final CredentialChange change) {
        final var adapter = new AdapterImpl() {
            @Override
            public void notifyChanged(final Notification notification) {
                if (notification.isTouch()) {
                    return;
                }
                final var changedValue = notification.getNewValue();
                if (changedValue instanceof ModifyEntity) {

                    final var entityValue = (ModifyEntity<?>) changedValue;
                    if (entityValue.getAffectedElement() instanceof Entity
                            && ((Entity) entityValue.getAffectedElement()).getId() != null) {
                        CacheCompromised.this.compromised.add(((Entity) entityValue.getAffectedElement()).getId());

                    }
                }
            }
        };

        change.eAdapters()
            .add(adapter);
    }

}
