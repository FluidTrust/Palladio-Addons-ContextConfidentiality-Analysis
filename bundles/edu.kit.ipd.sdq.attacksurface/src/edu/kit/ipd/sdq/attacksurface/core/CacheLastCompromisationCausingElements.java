package edu.kit.ipd.sdq.attacksurface.core;

import java.util.Stack;

import org.eclipse.emf.common.notify.Notification;
import org.eclipse.emf.common.notify.impl.AdapterImpl;
import org.eclipse.emf.common.util.EList;
import org.eclipse.emf.ecore.EObject;
import org.palladiosimulator.pcm.core.entity.Entity;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ModifyEntity;

public class CacheLastCompromisationCausingElements { 
    //TODO temporary, maybe implement rather a helper class for finding the causing elements of a compromisation

    private Stack<String> causes = new Stack<>();

    private static CacheLastCompromisationCausingElements cache = new CacheLastCompromisationCausingElements();

    private CacheLastCompromisationCausingElements() {
        // TODO Auto-generated constructor stub
    }

    public String popLastCauseId() {
        if (this.causes.isEmpty()) {
            return null;
        }
        return this.causes.pop();
    }

    public static CacheLastCompromisationCausingElements instance() {
        return cache;
    }

    public void reset() {
        this.causes.clear();
    }

    public void register(CredentialChange change) {
        var adapter = new AdapterImpl() {
            @Override
            public void notifyChanged(Notification notification) {
                if (notification.isTouch()) {
                    return;
                }
                var changedValue = notification.getNewValue();
                if (changedValue instanceof ModifyEntity) {

                    var entityValue = (ModifyEntity<?>) changedValue;
                    if (entityValue.getAffectedElement() instanceof Entity
                            && !entityValue.getCausingElements().isEmpty()) {
                                final var last = getLastEntity(entityValue.getCausingElements());
                                CacheLastCompromisationCausingElements.this.causes.push(last.getId()); //TODO test. also vuln. is entity
                    }
                }
            }

            private Entity getLastEntity(final EList<EObject> causingElements) {
                for (int i = causingElements.size() - 1; i >= 0; i--) {
                    if (causingElements.get(i) instanceof Entity) {
                        return (Entity) causingElements.get(i);
                    }
                }
                return null;
            }
        };

        change.eAdapters().add(adapter);
    }

}
