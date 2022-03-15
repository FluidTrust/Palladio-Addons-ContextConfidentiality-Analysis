package edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.context;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

import org.eclipse.emf.common.util.EList;
import org.eclipse.emf.ecore.EObject;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.HelperCreationCompromisedElements;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.DecisionType;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import com.google.common.base.Objects;

import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.ResourceContainerHandler;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.CauseGetter;
import edu.kit.ipd.sdq.attacksurface.graph.AttackGraph;
import edu.kit.ipd.sdq.attacksurface.graph.CVSurface;
import edu.kit.ipd.sdq.attacksurface.graph.CredentialSurface;
import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

/**
 * Represents an attack handler for resource containers attacks with contexts, i.e. credentials.
 * 
 * @author ugnwq
 * @version 1.0
 */
public class ResourceContainerContext extends ResourceContainerHandler {

    public ResourceContainerContext(final BlackboardWrapper modelStorage, final DataHandlerAttacker dataHandler,
            final AttackGraph attackGraph) {
        super(modelStorage, dataHandler, attackGraph);
    }

    @Override
    protected Optional<CompromisedResource> attackResourceContainer(final ResourceContainer container,
            final CredentialChange change, final Entity source) {
        final List<? extends UsageSpecification> credentials = this.getRelevantCredentials(change, container);

        final var result = this.queryAccessForEntity(container, credentials);

        if (result.isPresent() && Objects.equal(result.get().getDecision(), DecisionType.PERMIT)) {
            final var sourceList = this.createSource(source, credentials);
            final var compromised = HelperCreationCompromisedElements.createCompromisedResource(container, sourceList);
            return Optional.of(compromised);
        }
        return Optional.empty();

    }

    @Override
    protected Set<String> getCauses(EList<EObject> causingElements) {
        return CauseGetter.getCauses(causingElements, UsageSpecification.class);
    }

    @Override
    protected Function<String, CVSurface> getSurfaceMapper() {
        return CredentialSurface::new;
    }

}
