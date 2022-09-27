package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.Objects;

import org.palladiosimulator.pcm.core.entity.Entity;

/**
 * Class describing a node in the vulnerability graph. A node is an architectural element of the
 * type {@link Entity} (see also the description in https://doi.org/10.5445/IR/1000146787 )
 *
 * An ArchitectureNode is then identical when the id of the used Entity is the same.
 *
 * @author majuwa
 *
 */
public class ArchitectureNode {


    private Entity entity;

    /**
     * Creates an ArchitectureNode
     *
     * @param entity
     *            Entity should be an architectural Entity
     */
    public ArchitectureNode(Entity entity) {
        this.entity = entity;
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.entity.getId());
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        var other = (ArchitectureNode) obj;
        return Objects.equals(this.entity.getId(), other.entity.getId());
    }

    public Entity getEntity() {
        return this.entity;
    }

    @Override
    public String toString() {
        return String.format("\"%S%S\"", this.entity.getEntityName(), this.entity.getId());
    }

}
