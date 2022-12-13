package edu.kit.ipd.sdq.attacksurface.graph.algorithms;

import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.jgrapht.GraphPath;
import org.jgrapht.alg.shortestpath.PathValidator;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;
import org.palladiosimulator.pcm.confidentiality.context.system.AttributeProvider;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.MethodSpecification;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.PCMAttributeProvider;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.attacksurface.core.AttackHandlingHelper;
import edu.kit.ipd.sdq.attacksurface.graph.ArchitectureNode;
import edu.kit.ipd.sdq.attacksurface.graph.AttackEdge;
import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;

/**
 * Validator class to consider the attack surface filter during the attack path calculation. It
 * compares whether the current attack path has already added an edge which provides the initially
 * filtered {@link UsageSpecification}. If the attack path does not contain a {@link Vulnerability}
 * or {@link AttributeProvider} with the required credentials, an edge requiring these
 * {@link UsageSpecification}s invalids the attack path.
 *
 * @author majuwa
 * @version 1.0
 */
public class CredentialValidator implements PathValidator<ArchitectureNode, AttackEdge> {
    private final BlackboardWrapper modelStorage;
    private final List<UsageSpecification> initialBlockedCredentials;

    public CredentialValidator(final BlackboardWrapper modelStorage) {
        this.modelStorage = modelStorage;
        this.initialBlockedCredentials = Collections
            .unmodifiableList(AttackHandlingHelper.filteredCredentials(modelStorage));
    }

    @Override
    public boolean isValidPath(final GraphPath<ArchitectureNode, AttackEdge> graph, final AttackEdge newEdge) {
        final var initialCredentials = graph.getVertexList()
            .stream()
            .map(ArchitectureNode::getEntity)
            .flatMap(this::attributeProvider);
        final var gainedCredentialsVulnerability = graph.getEdgeList()
            .stream()
            .filter(e -> e.getCause() != null)
            .map(AttackEdge::getCause)
            .flatMap(e -> e.getGainedAttributes()
                .stream());

        final var gainedCredentialList = Stream.concat(initialCredentials, gainedCredentialsVulnerability)
            .toList();
        return !this.credentialCheck(newEdge, gainedCredentialList);

    }

    private boolean credentialCheck(final AttackEdge edge, final List<UsageSpecification> credentials) {
        if (edge.getCredentials() == null || edge.getCredentials()
            .isEmpty()) {
            return false;
        }
        final var blocked = edge.getCredentials()
            .stream()
            .filter(e -> this.initialBlockedCredentials.stream()
                .anyMatch(cred -> EcoreUtil.equals(cred.getAttribute(), e.getAttribute())
                        && EcoreUtil.equals(e.getAttributevalue(), cred.getAttributevalue())))
            .toList();
        return !blocked.stream()
            .allMatch(e -> credentials.stream()
                .anyMatch(cred -> EcoreUtil.equals(cred.getAttribute(), e.getAttribute())
                        && EcoreUtil.equals(e.getAttributevalue(), cred.getAttributevalue())));
    }

    private Stream<UsageSpecification> attributeProvider(final Entity entity) {
        return this.modelStorage.getSpecification()
            .getAttributeprovider()
            .stream()
            .filter(PCMAttributeProvider.class::isInstance)
            .map(PCMAttributeProvider.class::cast)
            .filter(e -> {
                if (entity instanceof AssemblyContext) {
                    return EcoreUtil.equals(e.getAssemblycontext(), entity);
                }
                if (entity instanceof LinkingResource) {
                    return EcoreUtil.equals(e.getLinkingresource(), entity);
                }
                if (entity instanceof ResourceContainer) {
                    return EcoreUtil.equals(e.getResourcecontainer(), entity);
                }
                if (entity instanceof MethodSpecification) {
                    return EcoreUtil.equals(e.getMethodspecification(), entity);
                }
                return false;
            })
            .map(PCMAttributeProvider::getAttribute);
    }

}
