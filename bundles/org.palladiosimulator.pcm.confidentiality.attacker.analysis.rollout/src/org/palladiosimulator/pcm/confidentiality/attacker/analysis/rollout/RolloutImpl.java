package org.palladiosimulator.pcm.confidentiality.attacker.analysis.rollout;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.osgi.service.component.annotations.Component;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PcmIntegrationFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.SystemIntegration;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.PCMBlackBoard;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.repository.RepositoryComponent;

/**
 * Class for rolling out the Annotations of {@link RepositoryComponent}s to
 * {@link AssemblyContext}s.
 *
 * @author majuwa
 * @author ugnwq
 */
@Component(service = RolloutImpl.class)
public class RolloutImpl implements Rollout<PCMBlackBoard, List<SystemIntegration>> {

    @Override
    public List<SystemIntegration> rollOut(final PCMBlackBoard test, final List<SystemIntegration> t) {
        final var listRollout = t.stream()
            .filter(this::isComponent)
            .toList();

        final var rolledOut = this.filter(t, listRollout);

        for (final var integration : listRollout) {
            final var list = this.getAssemblyContext(integration.getPcmelement()
                .getBasiccomponent(), test.getSystem())
                .stream()
                .map(assembly -> this.createIntegration(assembly, integration))
                .toList();
            rolledOut.addAll(list);
        }

        return rolledOut;

    }

    private SystemIntegration createIntegration(final AssemblyContext context, final SystemIntegration oldIntegration) {
        final var pcmElement = PcmIntegrationFactory.eINSTANCE.createPCMElement();
        pcmElement.getAssemblycontext()
            .add(context);
        final var integration = oldIntegration.getCopyExceptElement();
        integration.setPcmelement(pcmElement);

        return integration;

    }

    private List<AssemblyContext> getAssemblyContext(final RepositoryComponent component,
            final org.palladiosimulator.pcm.system.System system) {
        return system.getAssemblyContexts__ComposedStructure()
            .stream()
            .filter(e -> e.getEncapsulatedComponent__AssemblyContext()
                .getId()
                .equals(component.getId()))
            .toList();
    }

    private boolean isComponent(final SystemIntegration integration) {
        return integration.getPcmelement()
            .getBasiccomponent() != null;
    }

    private List<SystemIntegration> filter(final List<SystemIntegration> original,
            final List<SystemIntegration> filter) {

        return original.stream()
            .filter(e -> !this.containsHelper(e, filter))
            .collect(Collectors.toList());
    }

    private boolean containsHelper(final Entity entity, final List<? extends Entity> list) {
        return list.stream()
            .anyMatch(e -> Objects.equals(e.getId(), entity.getId()));
    }

}
