package org.palladiosimulator.pcm.confidentiality.context.attacksurface.api;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Attacker;
import org.palladiosimulator.pcm.confidentiality.context.ConfidentialAccessSpecification;
import org.palladiosimulator.pcm.confidentiality.context.analysis.api.ContextAnalysis;
import org.palladiosimulator.pcm.repository.Repository;

public interface AttackSurfaceAnalysis extends ContextAnalysis {
    boolean runAttackSurfaceAnalysis(Repository pcm, ConfidentialAccessSpecification context, Attacker adversary);

}
