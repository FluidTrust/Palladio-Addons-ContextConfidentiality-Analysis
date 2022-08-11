package edu.kit.ipd.sdq.attacksurface.tests.evaluation;

import static org.junit.jupiter.api.Assertions.fail;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.StringJoiner;
import java.util.stream.Collectors;

import org.eclipse.emf.common.util.EList;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.Assertions;
import org.palladiosimulator.pcm.confidentiality.attacker.helper.VulnerabilityHelper;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.MaximumPathLengthFilterCriterion;
import org.palladiosimulator.pcm.core.entity.Entity;

import de.uka.ipd.sdq.identifier.Identifier;
import edu.kit.ipd.sdq.attacksurface.graph.AttackEdge;
import edu.kit.ipd.sdq.attacksurface.graph.AttackGraphCreation;
import edu.kit.ipd.sdq.attacksurface.tests.change.AbstractChangeTests;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.AttackPath;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class EvaluationTest extends AbstractChangeTests {




    protected void pathsTestHelper(final CredentialChange changes, Entity targetedEntity) {

        var attackPath = changes.getAttackpaths();

        baseAttackPathTest(attackPath);

        var set = new HashSet<String>();
        for (var path : attackPath) {
            var element = path.getAttackpathelement().get(0).getAffectedElement().getId();
            if (set.contains(element)) {
                fail("Only one path for each element allowed");
            }
            set.add(element);
        }
        VulnerabilityHelper.initializeVulnerabilityStorage(getBlackboardWrapper().getVulnerabilitySpecification());
        var attackGraphCreation = new AttackGraphCreation(getBlackboardWrapper());

        attackGraphCreation.calculateAssemblyContextToAssemblyContextPropagation();
        attackGraphCreation.calculateAssemblyContextToGlobalAssemblyContextPropagation();
        attackGraphCreation.calculateAssemblyContextToLinkingResourcePropagation();
        attackGraphCreation.calculateAssemblyContextToLocalResourcePropagation();
        attackGraphCreation.calculateAssemblyContextToRemoteResourcePropagation();

        attackGraphCreation.calculateLinkingResourceToAssemblyContextPropagation();
        attackGraphCreation.calculateLinkingResourceToResourcePropagation();

        attackGraphCreation.calculateResourceContainerToLinkingResourcePropagation();
        attackGraphCreation.calculateResourceContainerToLocalAssemblyContextPropagation();
        attackGraphCreation.calculateResourceContainerToRemoteAssemblyContextPropagation();
        attackGraphCreation.calculateResourceContainerToResourcePropagation();

        var edges = attackGraphCreation.getGraph().edges();

        if (targetedEntity != null) {
            Assertions.assertTrue(
                    attackPath.stream().allMatch(e -> e.getTargetedElement().getId().equals(targetedEntity.getId())));
        }

        isConnectedPath(attackPath, edges);



//        final var attacked = getAttackGraph().getAttackedNodes();
//        final var compromised = getAttackGraph().getCompromisedNodes();
//        System.out.println("attacked: " + attacked);
//        System.out.println("attack edges: " + getAttackGraph().getEdges().stream().filter(e ->
//            attacked.contains(e.getNodes().source())).map(e -> e.createReverseEdge()).collect(Collectors.toSet()));
//        System.out.println("compromised: " + compromised);
//
//        System.out.println("\n\nAll attack edges:\n");
//        getAttackGraph().getEdges().forEach(e -> System.out.println(e.createReverseEdge()));
//
//        System.out.println("\n\ncredentials:\n");
//        System.out.println(getAttackGraph().getAllCredentials());
//        System.out.println("children of root: " + getAttackGraph().getChildrenOfNode(getAttackGraph().getRootNodeContent()));
//
//        Assert.assertTrue(getAttackGraph().getRootNodeContent().isCompromised());
//        if (isContainerOfRootCompromised) {
//            Assert.assertTrue(getAttackGraph().findNode(
//                new AttackNodeContent(
//                        getResource(getAttackGraph().getRootNodeContent()
//                                .getContainedElementAsPCMElement().getAssemblycontext()))).isCompromised());
//        }
//
//        final var surfacePaths = getAttackGraph().findAllAttackPaths(getBlackboardWrapper(), changes);
//        System.out.println("\n\nAll attack paths (surface):\n");
//        surfacePaths.forEach(p -> System.out.println(p));
//        final var attackPathGenerator = new AttackSurfaceAnalysis(true, getBlackboardWrapper());
//        final var paths = attackPathGenerator.toAttackPaths(surfacePaths, getBlackboardWrapper());
//        System.out.println("\n\nAll attack paths:\n");
//        printPaths(paths);
//        System.out.println(surfacePaths.size());
//        if (isSamePathAmountRequired) {
//            Assert.assertEquals(surfacePaths.size(), paths.size());
//        }
    }

    private void isConnectedPath(EList<AttackPath> attackPath, Set<AttackEdge> edges) {
        for (var path : attackPath) {
            var elements = path.getAttackpathelement();
            for (var i = 1; i < elements.size(); i++) {
                var origin = elements.get(i - 1).getAffectedElement();
                var target = elements.get(i).getAffectedElement();

                Assertions.assertTrue(edges.stream().anyMatch(e -> e.getRoot().getId().equals(origin.getId())
                        && e.getTarget().getId().equals(target.getId())));

            }
        }
    }

    private void baseAttackPathTest(EList<AttackPath> attackPath) {
        var allMatch = attackPath.stream().allMatch(e -> EcoreUtil
                .equals(e.getAttackpathelement().get(e.getAttackpathelement().size() - 1).getAffectedElement(),
                        e.getTargetedElement()));
        Assertions.assertTrue(allMatch);
    }

    protected String toString(
            final List<AttackPath> paths) {
        return toString(paths, "");
    }

    protected String toString(final List<AttackPath> paths, final String pathContainsFilter) {
        final var mainJoiner = new StringJoiner("\n");
        paths.forEach(p -> {
            final var joiner = new StringJoiner("\n");
            joiner.add(p.getAttackpathelement().size() + " PATH");
            if (!p.getCredentials().isEmpty()) {
                p.getCredentials().stream().sorted(this::compareIds).forEach(c -> {
                    final var credId = c.getId();
                    joiner.add("credentials initally necessary: " + credId);
                });
            }
            p.getAttackpathelement().forEach(s -> {
                final var id = !s.getCausingElements().isEmpty()
                        ? s.getCausingElements().stream().map(Entity.class::cast).map(Entity::getId)
                                .collect(Collectors.joining(""))
                        : "-";
                var name = s.getAffectedElement() != null ? s.getAffectedElement().getEntityName() : "";
                joiner.add(id + " | " + name);
            });
            p.getVulnerabilities().stream().sorted(this::compareIds).forEach(v -> {
                joiner.add("VULNs used: " + v.getId());
            });
            joiner.add("\n");
            final var joinerStr = joiner.toString();
            if (joinerStr.contains(pathContainsFilter)) {
                mainJoiner.add(joinerStr);
            }
        });
        return mainJoiner.toString();
    }

    private int compareIds(Identifier o1, Identifier o2) {
        return o1.getId().compareTo(o2.getId());
    }

    protected void printPaths(final List<AttackPath> paths) {
        System.out.println(toString(paths));
    }

    protected void setPathLengthFilter(final int maxLength) {
        if (getSurfaceAttacker().getFiltercriteria().stream()
                .noneMatch(MaximumPathLengthFilterCriterion.class::isInstance)) {
            final var maxPathLengthFilter = AttackerFactory.eINSTANCE.createMaximumPathLengthFilterCriterion();
            getSurfaceAttacker().getFiltercriteria().add(maxPathLengthFilter);
        }

        getSurfaceAttacker().getFiltercriteria()
            .stream()
            .filter(MaximumPathLengthFilterCriterion.class::isInstance)
            .map(MaximumPathLengthFilterCriterion.class::cast)
            .forEach(f -> f.setMaximumPathLength(maxLength));
    }
}
