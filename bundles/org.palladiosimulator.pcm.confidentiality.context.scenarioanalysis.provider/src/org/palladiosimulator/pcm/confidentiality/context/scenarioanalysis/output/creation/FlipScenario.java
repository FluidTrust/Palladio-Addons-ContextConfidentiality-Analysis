package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.output.creation;

import org.palladiosimulator.pcm.usagemodel.UsageScenario;

/**
 * Interface for flipping a scenario in case of missuage diagrams
 *
 * @author majuwa
 *
 */
public interface FlipScenario {

    void flip(UsageScenario scenario);

}
