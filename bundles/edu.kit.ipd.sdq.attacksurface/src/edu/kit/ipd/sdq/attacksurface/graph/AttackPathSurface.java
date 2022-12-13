package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.jgrapht.GraphPath;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.MethodSpecification;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.PCMAttributeProvider;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.AttackPath;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.AttackPathElement;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

/**
 * Represents an attack path in an {@link AttackGraph}.
 *
 * @author ugnwq, majuwa
 * @version 1.1
 */
public class AttackPathSurface {

    private final GraphPath<ArchitectureNode, AttackEdge> path;

    /**
     * Creates a new empty {@link AttackPathSurface}.
     */
    public AttackPathSurface(final GraphPath<ArchitectureNode, AttackEdge> path) {
        this.path = path;
    }

    /**
     *
     * @return the size of the path edge list, i.e. the count of edges
     */
    public int size() {
        return this.path.getLength();
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.path, this);
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if ((obj == null) || (this.getClass() != obj.getClass())) {
            return false;
        }
        final var other = (AttackPathSurface) obj;
        return Objects.equals(this.path, other.path);
    }

    @Override
    public String toString() {
        return "AttackPathSurface [path=" + this.path /*
                                                       * + ", initiallyNecessaryCredentials=" +
                                                       * this.initiallyNecessaryCredentials
                                                       */ + "]";
    }

    /**
     * Creates an output {@link AttackPath} from this path.
     *
     * @param modelStorage
     *            - the model storage
     * @param targetedEntity
     *            - the critical entity
     * @param doCreateCauselessPaths
     *            - whether a path should be created without causes (for temporary paths)
     * @return an {@link AttackPath} representing this attack path
     */
    public AttackPath toAttackPath(final BlackboardWrapper modelStorage, final Entity targetedEntity,
            final boolean doCreateCauselessPaths) {
        final var list = new ArrayList<AttackPathElement>();

        final var outputPath = KAMP4attackModificationmarksFactory.eINSTANCE.createAttackPath();
        outputPath.setTargetedElement(targetedEntity);

        final var startElement = KAMP4attackModificationmarksFactory.eINSTANCE.createAttackPathElement();
        startElement.setToolderived(false);
        startElement.setAffectedElement(this.path.getStartVertex()
            .getEntity());

        list.add(startElement);

        for (final var edge : this.path.getEdgeList()) {
            final var element = KAMP4attackModificationmarksFactory.eINSTANCE.createAttackPathElement();
            element.setToolderived(true);
            element.setAffectedElement(edge.getTarget());

            if (edge.getCause() != null) {
                element.getCausingElements()
                    .add(edge.getCause());
            }
            if (edge.getCredentials() != null) {
                edge.getCredentials()
                    .stream()
                    .forEach(element.getCausingElements()::add);
            }
            list.add(element);
        }

        outputPath.getAttackpathelement()
            .addAll(list);
        outputPath.getVulnerabilities()
            .addAll(this.getVulnerabilities(list));
        outputPath.getCredentials()
            .addAll(this.getCredentials(modelStorage, list));

        return outputPath;
    }

    private List<Vulnerability> getVulnerabilities(final List<AttackPathElement> elements) {
        return elements.parallelStream()
            .flatMap(e -> e.getCausingElements()
                .stream())
            .filter(Vulnerability.class::isInstance)
            .map(Vulnerability.class::cast)
            .toList();
    }

    private List<UsageSpecification> getCredentials(final BlackboardWrapper modelStorage,
            final List<AttackPathElement> elements) {
        final var necessaryCredentials = elements.parallelStream()
            .flatMap(e -> e.getCausingElements()
                .stream())
            .filter(UsageSpecification.class::isInstance)
            .map(UsageSpecification.class::cast)
            .toList();

        final var foundCredentialsElements = elements.parallelStream()
            .flatMap(e -> this.attributeProvider(modelStorage, e.getAffectedElement()))
            .toList();

        final var foundCredentialsVulnerabilities = this.getVulnerabilities(elements)
            .stream()
            .flatMap(e -> e.getGainedAttributes()
                .stream())
            .toList();

        final var foundCredenitals = new ArrayList<>(foundCredentialsElements);
        foundCredenitals.addAll(foundCredentialsVulnerabilities);

        return necessaryCredentials.parallelStream()
            .filter(e -> foundCredenitals.stream()
                .noneMatch(credential -> EcoreUtil.equals(credential.getAttribute(), e.getAttribute())
                        && EcoreUtil.equals(credential.getAttributevalue(), e.getAttributevalue())))
            .toList();

    }

    private Stream<UsageSpecification> attributeProvider(final BlackboardWrapper modelstorage, final Entity entity) {
        return modelstorage.getSpecification()
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
