package edu.kit.ipd.sdq.attacksurface.attackdag;

import java.util.Objects;

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
public class AttackStatusDescriptorNodeContent implements NodeContent<Entity> {
    private final Entity containedElement;
    private final PCMElementType type;
    private final PCMElement asPcmElement;
    
    //compromisation status
    private boolean compromised; //TODO at the moment takeover == compromised
    //TODO private boolean takeOver;
    
    public AttackStatusDescriptorNodeContent(final Entity containedEntity) {
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
    
    public ResourceContainer getContainedResourceContainer() {
        return this.asPcmElement.getResourcecontainer();
    }
    
    public LinkingResource getContainedLinkingResource() {
        return this.asPcmElement.getLinkingresource();
    }
    
    public AssemblyContext getContainedAssembly() {
        return this.asPcmElement.getAssemblycontext();
    }
    
    public MethodSpecification getContainedMethodSpecification() {
        return this.asPcmElement.getMethodspecification();
    }
    
    public boolean isCompromised() {
        return this.compromised;
    }

    public void setCompromised(final boolean compromised) {
        this.compromised = compromised;
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
        if (other instanceof AttackStatusDescriptorNodeContent) {
            final AttackStatusDescriptorNodeContent otherContent = (AttackStatusDescriptorNodeContent)other;
            return otherContent.containedElement.getId().equals(this.containedElement.getId());
        }
        return false;
    }
}
