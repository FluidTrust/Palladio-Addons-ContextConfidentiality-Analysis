package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackVector;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.core.entity.Entity;

/**
 * Class describing an edge in the attack graph. It connects two architectural elements and
 * represents an attack of the root element to the target element. It stores the reason for the
 * attack. The reason can either be a {@link Vulnerability}, a list of credentials (represented by
 * {@link UsageSpecification}) or a deployment relationship (represented by implicit). Additionally
 * it contains the {@link AttackVector}, which is how the elements are connected. The attack vector
 * is similar to the CVSS defintion.
 *
 * An {@link AttackEdge} is considered equal if its attributes are equals.
 *
 * @author majuwa
 *
 */
public class AttackEdge {

    /**
     * Causing Vulnerability
     */
    private final Vulnerability cause;

    private final List<? extends UsageSpecification> credentials;

    /**
     * represents a deployment relationship
     */
    private final boolean implicit;

    private final Entity root;

    private final Entity target;

    private final AttackVector vector;

    public AttackEdge(final Entity root, final Entity target, final Vulnerability cause,
            final List<? extends UsageSpecification> credentials) {
        this(root, target, cause, credentials, false, null);
    }

    public AttackEdge(final Entity root, final Entity target, final Vulnerability cause,
            final List<? extends UsageSpecification> credentials, final boolean implicit, final AttackVector vector) {
        if (!implicit && ((cause == null && credentials == null) || (credentials != null && credentials.isEmpty()))) {
            throw new IllegalArgumentException("cause or credentials required");
        }

        this.root = root;
        this.target = target;
        this.cause = cause;
        this.credentials = credentials == null ? List.of() : credentials;
        this.implicit = implicit;
        this.vector = vector;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if ((obj == null) || (this.getClass() != obj.getClass())) {
            return false;
        }
        final var other = (AttackEdge) obj;

        if (this.cause == null && other.cause == null) {
            return this.checkComparision(other);
        }

        else if (this.cause != null && other.cause != null) {
            return Objects.equals(this.cause.getId(), other.cause.getId()) && this.checkComparision(other);

        }
        return false;
    }

    public final Vulnerability getCause() {
        return this.cause;
    }

    public final List<? extends UsageSpecification> getCredentials() {
        return this.credentials;
    }

    public final Entity getRoot() {
        return this.root;
    }

    public final Entity getTarget() {
        return this.target;
    }

    public final AttackVector getVector() {
        return this.vector;
    }

    // TODO fix credentials id
    @Override
    public int hashCode() {
        final var hash = Objects.hash(this.root.getId(), this.target.getId());

        if (this.cause == null) {
            return Objects.hash(this.credentials, this.implicit, this.vector, hash);
        } else {
            return Objects.hash(this.cause.getId(), this.vector, hash);
        }
    }

    public final boolean isImplicit() {
        return this.implicit;
    }

    @Override
    public String toString() {
        if (this.cause == null) {
            return "AttackEdge [content=" + this.credentials.stream()
                .map(e -> e.getAttribute()
                    .getEntityName()
                        + e.getAttributevalue()
                            .getValues())
                .collect(Collectors.joining(",")) + ", " + this.root.getEntityName() + " -> "
                    + this.target.getEntityName() + "]";
        }
        return "AttackEdge [content=" + this.cause + ", " + this.root.getEntityName() + " -> "
                + this.target.getEntityName() + "]";
    }

    private boolean checkComparision(final AttackEdge other) {
        return EcoreUtil.equals(this.credentials, other.credentials) && this.implicit == other.implicit
                && Objects.equals(this.vector, other.vector) && Objects.equals(this.root.getId(), other.root.getId())
                && Objects.equals(this.target.getId(), other.getTarget()
                    .getId());
    }

}
