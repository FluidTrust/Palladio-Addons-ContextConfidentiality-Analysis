package edu.kit.ipd.sdq.attacksurface.tests.evaluation;

import java.util.List;
import java.util.StringJoiner;
import java.util.stream.Collectors;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.MaximumPathLengthFilterCriterion;
import org.palladiosimulator.pcm.core.entity.Entity;

import de.uka.ipd.sdq.identifier.Identifier;
import edu.kit.ipd.sdq.attacksurface.tests.change.AbstractChangeTests;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.AttackPath;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class EvaluationTest extends AbstractChangeTests {



    protected void pathsTestHelper(final CredentialChange changes, final boolean isContainerOfRootCompromised,
            final boolean isSamePathAmountRequired) {
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
