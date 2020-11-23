package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.output.creation;

import java.util.List;

import org.palladiosimulator.pcm.confidentiality.context.set.ContextSet;
import org.palladiosimulator.pcm.core.composition.Connector;
import org.palladiosimulator.pcm.repository.OperationInterface;
import org.palladiosimulator.pcm.repository.OperationSignature;
import org.palladiosimulator.pcm.usagemodel.UsageScenario;

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
    public void storeNegativeResult(UsageScenario scenario, OperationInterface operationInterface,
            OperationSignature signature, Connector connector, ContextSet requestor, List<ContextSet> policies);

    /**
     * 
     * @param scenario
     * @throws IllegalStateException
     *             if a negative result was stored previously
     * @throws NullPointerException
     *             if the argument is null
     */
    public void storePositiveResult(UsageScenario scenario);

}
