package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.List;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackVector;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;

public class AttackEdge {

    private Vulnerability cause;
    private List<? extends UsageSpecification> credentials;
    private boolean implicit;
    private AttackVector vector;

    public AttackEdge(Vulnerability cause, List<? extends UsageSpecification> credentials, boolean implicit,
            AttackVector vector) {
        this.cause = cause;
        this.credentials = credentials;
        this.implicit = implicit;
        this.vector = vector;
    }

    public AttackEdge(Vulnerability cause, List<? extends UsageSpecification> credentials) {
        this(cause, credentials, false, null);
    }

}
