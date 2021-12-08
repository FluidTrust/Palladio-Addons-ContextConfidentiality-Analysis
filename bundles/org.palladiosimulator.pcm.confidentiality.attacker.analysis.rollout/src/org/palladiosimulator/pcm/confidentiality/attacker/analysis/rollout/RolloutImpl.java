package org.palladiosimulator.pcm.confidentiality.attacker.analysis.rollout;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.EObject;
import org.osgi.service.component.annotations.Component;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.NonGlobalCommunication;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PcmIntegrationFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.RoleSystemIntegration;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.SystemIntegration;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.VulnerabilitySystemIntegration;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.util.PcmIntegrationSwitch;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.PCMBlackBoard;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.repository.RepositoryComponent;

/**
 * Class for rolling out the Annotations of {@link RepositoryComponent}s to
 * {@link AssemblyContext}s.
 *
 * @author majuwa
 *
 */
@Component(service = RolloutImpl.class)
public class RolloutImpl implements Rollout<PCMBlackBoard, List<SystemIntegration>> {

    @Override
    public List<SystemIntegration> rollOut(PCMBlackBoard test, List<SystemIntegration> t) {
        var listRollout = t.stream().filter(this::isComponent).collect(Collectors.toList());

        var rolledOut = filter(t, listRollout);

        for (var integration : listRollout) {
            var list = getAssemblyContext(integration.getPcmelement().getBasiccomponent(), test.getSystem()).stream()
                    .map(assembly -> createIntegration(assembly,
                            integration))
                    .collect(Collectors.toList());
            rolledOut.addAll(list);
        }

        return rolledOut;

    }

    private SystemIntegration createIntegration(
            AssemblyContext context, SystemIntegration oldIntegration) {
        var pcmElement = PcmIntegrationFactory.eINSTANCE.createPCMElement();
        pcmElement.setAssemblycontext(context);


        var systemSwitch = new PcmIntegrationSwitch<SystemIntegration>() {
            @Override
            public SystemIntegration caseVulnerabilitySystemIntegration(VulnerabilitySystemIntegration object) {
                var integration = PcmIntegrationFactory.eINSTANCE.createVulnerabilitySystemIntegration();
                integration.setVulnerability(object.getVulnerability());
                return integration;
            }

            @Override
            public SystemIntegration caseRoleSystemIntegration(RoleSystemIntegration object) {
                var integration = PcmIntegrationFactory.eINSTANCE.createRoleSystemIntegration();
                integration.setRole(object.getRole());
                return integration;
            }

            @Override
            public SystemIntegration caseNonGlobalCommunication(NonGlobalCommunication object) {
                return PcmIntegrationFactory.eINSTANCE.createNonGlobalCommunication();
            }

            @Override
            public SystemIntegration defaultCase(EObject object) {
                throw new IllegalStateException("Unkown Element");
            }
        };

        var integration = systemSwitch.doSwitch(oldIntegration);
        integration.setPcmelement(pcmElement);

        return integration;

    }

    private List<AssemblyContext> getAssemblyContext(RepositoryComponent component,
            org.palladiosimulator.pcm.system.System system) {
        return system.getAssemblyContexts__ComposedStructure().stream()
                .filter(e -> e.getEncapsulatedComponent__AssemblyContext().getId().equals(component.getId()))
                .collect(Collectors.toList());
    }

    private boolean isComponent(SystemIntegration integration) {
        return integration.getPcmelement().getBasiccomponent() != null;
    }

    private List<SystemIntegration> filter(List<SystemIntegration> original,
            List<SystemIntegration> filter) {

        return original.stream().filter(e -> !containsHelper(e, filter)).collect(Collectors.toList());
    }

    private boolean containsHelper(Entity entity, List<? extends Entity> list) {
        return list.stream().anyMatch(e -> Objects.equals(e.getId(), entity.getId()));
    }

}
