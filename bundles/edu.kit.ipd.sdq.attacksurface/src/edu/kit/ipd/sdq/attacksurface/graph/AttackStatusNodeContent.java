package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PCMElement;
import org.palladiosimulator.pcm.core.entity.Entity;

/**
 * Represents a {@link NodeContent} containing the attack status for an element.
 * 
 * @author ugnwq
 * @version 1.0
 */
public class AttackStatusNodeContent implements NodeContent<Entity> {
    private final Entity containedElement;
    private final PCMElementType type;
    private final PCMElement asPcmElement;
    
    //visitation status
    private boolean visited;
    
    //compromisation status
    private CompromisationStatus status;
    private final Set<AttackStatusNodeContent> attackerNodes;
    
    // tmp set for necessary credential causes
    private final Set<CredentialsVulnearbilitiesSurface> initiallyNecessaryCauses;
    
    public AttackStatusNodeContent(final Entity containedEntity) {
        this.containedElement = Objects.requireNonNull(containedEntity);
        this.type = PCMElementType.typeOf(containedEntity);
        if (this.type == null) {
            throw new IllegalArgumentException("unknown entity type for class \"" + 
                    containedEntity.getClass().getName() + "\"");
        }
        this.asPcmElement = this.type.toPCMElement(this.containedElement);
        this.status = CompromisationStatus.NOT_COMPROMISED;
        this.attackerNodes = new HashSet<>();
        this.initiallyNecessaryCauses = new HashSet<>();
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
    
    /**
     * 
     * @return whether the node was attacked, i.e. at least one credential was extracted
     */
    public boolean isAttacked() {
        return this.status.getSeverity() > 0;
    }
    
    /**
     * 
     * @return whether the node is compromised, i.e. it is completely taken over
     */
    public boolean isCompromised() {
        return this.status.equals(CompromisationStatus.COMPROMISED);
    }
    
    /**
     * 
     * @param attackerNode
     * @return whether this node is attacked by the given attacker node
     */
    public boolean isAttackedBy(AttackStatusNodeContent attackerNode) {
        return this.attackerNodes.contains(attackerNode);
    }

    /**
     * Sets the node comromised.
     * 
     * @param sourceNode - the attacker node
     */
    public void compromise(final AttackStatusNodeContent sourceNode) {
        this.attackerNodes.add(sourceNode);
        this.status = CompromisationStatus.COMPROMISED;
    }

    /**
     * Sets the node attacked if it is not yet compromised.
     * 
     * @param sourceNode - the attacker node 
     */
    public void attack(final AttackStatusNodeContent sourceNode) {
        this.attackerNodes.add(sourceNode);
        this.status = isCompromised() ? this.status : CompromisationStatus.ATTACKED_AND_CREDENTIALS_EXTRACTED;
    }

    /**
     * 
     * @return whether the node was already visited
     */
    public boolean isVisited() {
        return this.visited;
    }

    /**
     * 
     * @param visited - the visitation status to be set
     */
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

    /**
     * 
     * @param necessaryCauses - adds the given necessary causes to the node
     */
    public void addInitiallyNecessaryCredentials(Set<CredentialsVulnearbilitiesSurface> necessaryCauses) {
        this.initiallyNecessaryCauses.addAll(necessaryCauses);
    }
    
    /**
     * 
     * @param setToBeFilled - fills the set with initially nessecary causes of this node
     */
    public void copyAllNecessaryCausesToSet(final Set<CredentialSurface> setToBeFilled) { //TODO: return Set 
        this.initiallyNecessaryCauses.forEach(c -> setToBeFilled.add(new CredentialSurface(c.getCause())));
    }
}
