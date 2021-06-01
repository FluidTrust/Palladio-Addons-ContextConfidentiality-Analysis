package org.palladiosimulator.pcm.confidentiality.context.attackeranalysis.api;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Attacker;
import org.palladiosimulator.pcm.confidentiality.context.ConfidentialAccessSpecification;
import org.palladiosimulator.pcm.confidentiality.context.analysis.api.ContextAnalysis;
import org.palladiosimulator.pcm.repository.Repository;

public interface AttackerAnalysis extends ContextAnalysis {
    boolean runAttackerAnalysis(Repository pcm, ConfidentialAccessSpecification context, Attacker adversary);

}
