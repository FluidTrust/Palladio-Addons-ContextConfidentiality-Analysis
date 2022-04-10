package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.output.creation;

import java.util.List;

import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceSpecification;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.PDPResult;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.composition.Connector;
import org.palladiosimulator.pcm.repository.Signature;
import org.palladiosimulator.pcm.seff.ExternalCallAction;
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
     * @param seff
     * @throws IllegalStateException
     *             in case previously a positive result was stored for the usagescenaio
     * @throws NullPointerException
     *             if one argument is null
     */
    void storeResult(UsageScenario scenario, Signature signature,
            Identifier seff, Connector connector, PDPResult decision, List<AssemblyContext> assembly,
            ServiceSpecification originService, ExternalCallAction action);

}
