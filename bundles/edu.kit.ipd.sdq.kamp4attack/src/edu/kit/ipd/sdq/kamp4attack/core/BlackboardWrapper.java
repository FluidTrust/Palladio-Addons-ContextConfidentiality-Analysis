package edu.kit.ipd.sdq.kamp4attack.core;

import org.palladiosimulator.pcm.allocation.Allocation;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.VulnerabilitySystemSpecification;
import org.palladiosimulator.pcm.confidentiality.context.system.SystemSpecificationContainer;
import org.palladiosimulator.pcm.resourceenvironment.ResourceEnvironment;
import org.palladiosimulator.pcm.system.System;

import de.uka.ipd.sdq.workflow.mdsd.blackboard.MDSDBlackboard;
import edu.kit.ipd.sdq.kamp.architecture.AbstractArchitectureVersion;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.AbstractKAMP4attackModificationRepository;

/**
 * This class wraps the MDSD Blackboard {@link MDSDBlackboard}
 *
 *
 * @author Maximilian Walter
 *
 */

public class BlackboardWrapper extends AbstractArchitectureVersion<AbstractKAMP4attackModificationRepository<?>> {

    private final System assembly;
    private final ResourceEnvironment environment;
    private final Allocation allocation;
    private final SystemSpecificationContainer pcmSpecification;
    private final VulnerabilitySystemSpecification vulnerabilitySpecification;

    public BlackboardWrapper(final AbstractKAMP4attackModificationRepository<?> blackboard, final System assembly,
            final ResourceEnvironment environment, final Allocation allocation,
            final SystemSpecificationContainer pcmSpecification,
            final VulnerabilitySystemSpecification vulnerabilitySpecification) {
        super("", blackboard);
        this.assembly = assembly;
        this.environment = environment;
        this.allocation = allocation;
        this.pcmSpecification = pcmSpecification;
        this.vulnerabilitySpecification = vulnerabilitySpecification;
    }

    /**
     * Gets the {@link System}
     *
     * @return Returns the system of the current PCM model
     */
    public System getAssembly() {
        return this.assembly;
    }

    public ResourceEnvironment getResourceEnvironment() {
        return this.environment;
    }

    public Allocation getAllocation() {
        return this.allocation;
    }

    public SystemSpecificationContainer getSpecification() {
        return this.pcmSpecification;
    }

    public VulnerabilitySystemSpecification getVulnerabilitySpecification() {
        return this.vulnerabilitySpecification;
    }

}
