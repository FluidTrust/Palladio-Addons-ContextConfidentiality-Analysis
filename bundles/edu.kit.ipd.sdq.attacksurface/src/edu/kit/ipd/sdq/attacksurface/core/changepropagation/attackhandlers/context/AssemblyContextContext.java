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
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;

import com.google.common.base.Objects;

import de.uka.ipd.sdq.identifier.Identifier;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.CauseGetter;
import edu.kit.ipd.sdq.attacksurface.graph.AttackGraph;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusNodeContent;
import edu.kit.ipd.sdq.attacksurface.graph.CredentialSurface;
import edu.kit.ipd.sdq.attacksurface.graph.CredentialsVulnearbilitiesSurface;
import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

/**
 * Represents an attack handler for assembly context attacks with contexts, i.e. credentials.
 *
 * @author ugnwq
 * @version 1.0
 */
public class AssemblyContextContext extends AssemblyContextHandler {

    public AssemblyContextContext(final BlackboardWrapper modelStorage, final DataHandlerAttacker dataHandler,
            final AttackGraph attackGraph) {
        super(modelStorage, dataHandler, attackGraph);
    }

    @Override
    protected Optional<CompromisedAssembly> attackComponent(final AssemblyContext component,
            final CredentialChange change, final Entity source) {
        final List<? extends UsageSpecification> credentials =
                getRelevantCredentials(new AttackStatusNodeContent(source),
                        new AttackStatusNodeContent(component));

        final var result = this.queryAccessForEntity(component, credentials);

        if (result.isPresent() && Objects.equal(result.get().decision(), DecisionType.PERMIT)) {
            final var sourceList = createSource(source, credentials);
            final var compromised = HelperCreationCompromisedElements.createCompromisedAssembly(component, sourceList);
            return Optional.of(compromised);
        }
        return Optional.empty();
    }

    @Override
    protected Set<Identifier> getCauses(EList<EObject> causingElements) {
        return CauseGetter.getCauses(causingElements, UsageSpecification.class);
    }

    @Override
    protected Function<Identifier, CredentialsVulnearbilitiesSurface> getSurfaceMapper() {
        return CredentialSurface::new;
    }

}