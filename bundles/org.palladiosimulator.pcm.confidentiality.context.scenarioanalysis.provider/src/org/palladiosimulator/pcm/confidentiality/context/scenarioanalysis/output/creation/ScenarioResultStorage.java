package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.output.creation;

import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.PDPResult;
import org.palladiosimulator.pcm.repository.OperationInterface;
import org.palladiosimulator.pcm.repository.Signature;
import org.palladiosimulator.pcm.usagemodel.UsageScenario;

import de.uka.ipd.sdq.identifier.Identifier;

/**
 * Interface for storing the results of the scenario analysis
 *
 * @author majuwa
 *
 */
public interface ScenarioResultStorage {

    /**
     * Adds a negative result for a {@link UsageScenario}. By adding it checks, whether a positive
     * result was already stored for UsageScenario.
     *
     * @param scenario
     * @param operationInterface
     * @param signature
     * @param connector
     * @throws IllegalStateException
     *             in case previously a positive result was stored for the usagescenaio
     * @throws NullPointerException
     *             if one argument is null
     */
    void storeNegativeResult(UsageScenario scenario, OperationInterface operationInterface, Signature signature,
            Identifier connector, PDPResult requestor);

    /**
     *
     * @param scenario
     * @throws IllegalStateException
     *             if a negative result was stored previously
     * @throws NullPointerException
     *             if the argument is null
     */
    void storePositiveResult(UsageScenario scenario, PDPResult requestor);

    void storePositiveResult(UsageScenario scenario);

}
