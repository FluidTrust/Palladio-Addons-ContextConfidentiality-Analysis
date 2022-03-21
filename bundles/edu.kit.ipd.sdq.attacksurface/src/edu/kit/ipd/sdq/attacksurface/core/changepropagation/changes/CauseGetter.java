package edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes;

import java.util.Set;
import java.util.stream.Collectors;

import org.eclipse.emf.common.util.EList;
import org.eclipse.emf.ecore.EObject;
import org.palladiosimulator.pcm.core.entity.Entity;

import de.uka.ipd.sdq.identifier.Identifier;

/**
 * Helper class to get IDs of causes of a certain kind from causing elements.
 * 
 * @author ugnwq
 * @version 1.0
 */
public final class CauseGetter {
    private CauseGetter() {
        
    }
    
    /**
     * 
     * @param causingElements - the list of causing elements
     * @param toFindInterface - the kind of causes to be found
     * @return set of causes of the given kind
     */
    public static Set<Identifier> getCauses(final EList<EObject> causingElements, final Class<? extends Entity> toFindInterface) {
        return causingElements
                .stream()
                .filter(toFindInterface::isInstance)
                .map(toFindInterface::cast)
                .collect(Collectors.toSet());
    }
}
