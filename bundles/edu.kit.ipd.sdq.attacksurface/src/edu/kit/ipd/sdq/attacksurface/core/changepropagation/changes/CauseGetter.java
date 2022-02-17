package edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes;

import java.util.Set;
import java.util.stream.Collectors;

import org.eclipse.emf.common.util.EList;
import org.eclipse.emf.ecore.EObject;
import org.palladiosimulator.pcm.core.entity.Entity;

import de.uka.ipd.sdq.identifier.Identifier;

public final class CauseGetter {
    private CauseGetter() {
        
    }
    
    public static Set<String> getCauses(final EList<EObject> causingElements, final Class<? extends Entity> toFindInterface) {
        return causingElements
                .stream()
                .filter(toFindInterface::isInstance)
                .map(toFindInterface::cast)
                .map(Identifier::getId)
                .collect(Collectors.toSet());
    }
}
