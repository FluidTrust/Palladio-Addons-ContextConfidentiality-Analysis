package org.palladiosimulator.pcm.confidentiality.context.analysis.api;

import edu.kit.kastel.scbs.confidentiality.ConfidentialitySpecification;
import edu.kit.kastel.scbs.confidentiality.adversary.Adversaries;
import org.palladiosimulator.pcm.confidentiality.context.model.Context;
import org.palladiosimulator.pcm.repository.Repository;
public interface AttackerAnalysis {
    boolean runAttackerAnalysis(Repository pcm, Context context, Adversaries adversary, ConfidentialitySpecification data );

}
