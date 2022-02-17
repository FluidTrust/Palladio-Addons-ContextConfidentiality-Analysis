package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PCMElement;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.MethodSpecification;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

/**
 * Represents a {@link NodeContent} containing the attack status for an element.
 * TODO: at the moment only for {@link AssemblyContext}s.
 * 
 * @author ugnwq
 * @version 1.0
 */
public class AttackStatusNodeContent implements NodeContent<Entity> {
    //TODO adapt
    
    private final Entity containedElement;
    private final PCMElementType type;
    private final PCMElement asPcmElement;
    
    //visitation status
    private boolean visited;
    
    //compromisation status
    private boolean isCompromised; //TODO at the moment takeover == compromised
    //TODO private boolean takeOver;
    
    public AttackStatusNodeContent(final Entity containedEntity) {
        this.containedElement = Objects.requireNonNull(containedEntity);
        this.type = PCMElementType.typeOf(containedEntity);
        if (this.type == null) {
            throw new IllegalArgumentException("unknown entity type for class \"" + 
                    containedEntity.getClass().getName() + "\"");
        }
        this.asPcmElement = this.type.toPCMElement(this.containedElement);
    }

    @Override
    public Entity getContainedElement() {
        return this.containedElement;
    }
    
    public PCMElement getContainedElementAsPCMElement() {
        return this.asPcmElement;
    }
    
    public PCMElementType getTypeOfContainedElement() {
        return this.type;
    }
    
    public boolean isCompromised() {
        return this.isCompromised;
    }

    public void setCompromised(final boolean isCompromised) {
        this.isCompromised = isCompromised;
    }

    public boolean isVisited() {
        return this.visited;
    }

    public void setVisited(boolean visited) {
        this.visited = visited;
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.containedElement.getId());
    }
    
    @Override
    public boolean equals(final Object other) {
        if (this == other) {
            return true;
        }
        if (other == null) {
            return false;
        }
        if (other instanceof AttackStatusNodeContent) {
            final AttackStatusNodeContent otherContent = (AttackStatusNodeContent)other;
            return otherContent.containedElement.getId().equals(this.containedElement.getId());
        }
        return false;
    }
    
    @Override
    public String toString() {
        return "(id= " + containedElement.getId() + "name = " + containedElement.getEntityName() + ")";
    }
}
