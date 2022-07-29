package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackVector;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.core.entity.Entity;

public class AttackEdge {

    public final Vulnerability getCause() {
        return this.cause;
    }

    public final List<? extends UsageSpecification> getCredentials() {
        return this.credentials;
    }

    public final boolean isImplicit() {
        return this.implicit;
    }

    public final AttackVector getVector() {
        return this.vector;
    }

    public final Entity getRoot() {
        return this.root;
    }

    public final Entity getTarget() {
        return this.target;
    }

    private Vulnerability cause;
    private List<? extends UsageSpecification> credentials;
    private boolean implicit;
    private AttackVector vector;

    private Entity root;
    private Entity target;

    public AttackEdge(Entity root, Entity target, Vulnerability cause, List<? extends UsageSpecification> credentials,
            boolean implicit,
            AttackVector vector) {
        if (!implicit && ((cause == null && credentials == null) || (credentials != null && credentials.isEmpty()))) {
            throw new IllegalArgumentException("cause or credentials required");
        }


        this.root = root;
        this.target = target;
        this.cause = cause;
        this.credentials = credentials;
        this.implicit = implicit;
        this.vector = vector;
    }

    public AttackEdge(Entity root, Entity target, Vulnerability cause, List<? extends UsageSpecification> credentials) {
        this(root, target, cause, credentials, false, null);
    }

    // TODO fix credentials id
    @Override
    public int hashCode() {
        var hash = Objects.hash(this.root.getId(), this.target.getId());

        if (this.cause == null) {
            return Objects.hash(this.credentials, this.implicit, this.vector, hash);
        } else {
            return Objects.hash(this.cause.getId(), this.vector, hash);
        }
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
        var other = (AttackEdge) obj;

        if (this.cause == null && other.cause == null) {
            return Objects.equals(this.credentials, other.credentials) && this.implicit == other.implicit
                    && this.vector == other.vector && Objects.equals(this.root.getId(), this.target.getId());
        }

        else if (this.cause != null && other.cause != null) {
            return Objects.equals(this.cause.getId(), other.cause.getId())
                    && Objects.equals(this.credentials, other.credentials) && this.implicit == other.implicit
                    && this.vector == other.vector && Objects.equals(this.root.getId(), this.target.getId());
        }
        return false;
    }

    @Override
    public String toString() {
        if (this.cause == null) {
            return "AttackEdge [content="
                    + this.credentials.stream()
                            .map(e -> e.getAttribute().getEntityName() + e.getAttributevalue().getValues())
                            .collect(Collectors.joining(","))
                    + ", " + this.root.getEntityName()
                    + " -> "
                    + this.target.getEntityName() + "]";
        }
        return "AttackEdge [content="
                + this.cause + ", "
                + this.root.getEntityName() + " -> " + this.target.getEntityName() + "]";
    }

}
