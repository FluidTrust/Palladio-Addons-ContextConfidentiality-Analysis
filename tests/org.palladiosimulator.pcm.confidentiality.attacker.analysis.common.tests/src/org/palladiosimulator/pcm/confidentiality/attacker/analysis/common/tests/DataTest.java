package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandler;
import org.palladiosimulator.pcm.repository.ParameterModifier;
import org.palladiosimulator.pcm.seff.ResourceDemandingSEFF;

import apiControlFlowInterfaces.Repo;
import factory.FluentRepositoryFactory;
import repositoryStructure.internals.Primitive;

public class DataTest {

    private Repo repo;
    private FluentRepositoryFactory create;

    @BeforeEach
    void prepare() {
        create = new FluentRepositoryFactory();
        repo = create.newRepository();
    }

    @Test
    void testExtractionRepositoryParameters() {

        repo.addToRepository(
                create.newCompositeDataType().withName("TestDataType").withInnerDeclaration("Test", Primitive.STRING));
        var operationSignature = create.newOperationSignature().withName("test").withParameter("test",
                create.fetchOfDataType("TestDataType"), ParameterModifier.NONE);
        var repository = repo
                .addToRepository(
                        create.newOperationInterface().withName("Test").withOperationSignature(operationSignature))
                .addToRepository(create.newBasicComponent().withName("TestComponent")
                        .withServiceEffectSpecification(create.newSeff().onSignature(create.fetchOfSignature("test")))
                        .provides(create.fetchOfOperationInterface("Test")))
                .createRepositoryNow();

        var component = create.fetchOfBasicComponent("TestComponent");
        var data = DataHandler.getData(component);

        assertEquals(1, data.size());

        assertTrue(data.stream().anyMatch(e -> {
            return e.getReferenceName().equals("test")
                    && EcoreUtil.equals(e.getSource(), create.fetchOfComponent("TestComponent"))
                    && EcoreUtil.equals(e.getDataType(), create.fetchOfCompositeDataType("TestDataType"));
        }));

    }

    @Test
    void testExtractionRepositoryReturnValuesDefault() {

        repo.addToRepository(
                create.newCompositeDataType().withName("TestDataType").withInnerDeclaration("Test", Primitive.STRING));
        var operationSignature = create.newOperationSignature().withName("test").withReturnType(Primitive.BOOLEAN);
        var repository = repo
                .addToRepository(
                        create.newOperationInterface().withName("Test").withOperationSignature(operationSignature))
                .addToRepository(create.newBasicComponent().withName("TestComponent")
                        .withServiceEffectSpecification(create.newSeff().onSignature(create.fetchOfSignature("test")))
                        .provides(create.fetchOfOperationInterface("Test")))
                .createRepositoryNow();

        var component = create.fetchOfBasicComponent("TestComponent");
        var data = DataHandler.getData(component);

        assertEquals(1, data.size());

        assertTrue(data.stream().anyMatch(e -> {
            return EcoreUtil.equals(e.getSource(), create.fetchOfSignature("test"))
                    && EcoreUtil.equals(e.getDataType(), create.fetchOfDataType(Primitive.BOOLEAN));
        }));

    }

    @Test
    void testExtractionRepositoryReturnValuesComplex() {

        repo.addToRepository(
                create.newCompositeDataType().withName("TestDataType").withInnerDeclaration("Test", Primitive.STRING));
        var operationSignature = create.newOperationSignature().withName("test")
                .withReturnType(create.fetchOfDataType("TestDataType"));
        var repository = repo
                .addToRepository(
                        create.newOperationInterface().withName("Test").withOperationSignature(operationSignature))
                .addToRepository(create.newBasicComponent().withName("TestComponent")
                        .withServiceEffectSpecification(create.newSeff().onSignature(create.fetchOfSignature("test")))
                        .provides(create.fetchOfOperationInterface("Test")))
                .createRepositoryNow();

        var component = create.fetchOfBasicComponent("TestComponent");
        var data = DataHandler.getData(component);

        assertEquals(1, data.size());

        assertTrue(data.stream().anyMatch(e -> {
            return EcoreUtil.equals(e.getSource(), create.fetchOfSignature("test"))
                    && EcoreUtil.equals(e.getDataType(), create.fetchOfDataType("TestDataType"));
        }));

    }

    @Test
    void testExtractionRepositoryReturnValuesInteger() {

        repo.addToRepository(
                create.newCompositeDataType().withName("TestDataType").withInnerDeclaration("Test", Primitive.STRING));
        var operationSignature = create.newOperationSignature().withName("test")
                .withReturnType(create.fetchOfDataType(Primitive.INTEGER));
        var repository = repo
                .addToRepository(
                        create.newOperationInterface().withName("Test").withOperationSignature(operationSignature))
                .addToRepository(create.newBasicComponent().withName("TestComponent")
                        .withServiceEffectSpecification(create.newSeff().onSignature(create.fetchOfSignature("test")))
                        .provides(create.fetchOfOperationInterface("Test")))
                .createRepositoryNow();

        var component = create.fetchOfBasicComponent("TestComponent");
        var data = DataHandler.getData(component);

        assertEquals(1, data.size());

        assertTrue(data.stream().anyMatch(e -> {
            return EcoreUtil.equals(e.getSource(), create.fetchOfSignature("test"))
                    && EcoreUtil.equals(e.getDataType(), create.fetchOfDataType(Primitive.INTEGER));
        }));

    }

    @Test
    void testExtractionRepositoryParametersReturnValue() {

        repo.addToRepository(
                create.newCompositeDataType().withName("TestDataType").withInnerDeclaration("Test", Primitive.STRING));
        var operationSignature = create.newOperationSignature().withName("test")
                .withParameter("test", create.fetchOfDataType("TestDataType"), ParameterModifier.NONE)
                .withReturnType(create.fetchOfDataType(Primitive.INTEGER));
        var repository = repo
                .addToRepository(
                        create.newOperationInterface().withName("Test").withOperationSignature(operationSignature))
                .addToRepository(create.newBasicComponent().withName("TestComponent")
                        .withServiceEffectSpecification(create.newSeff().onSignature(create.fetchOfSignature("test")))
                        .provides(create.fetchOfOperationInterface("Test")))
                .createRepositoryNow();

        var component = create.fetchOfBasicComponent("TestComponent");
        var data = DataHandler.getData(component);

        assertEquals(2, data.size());

        assertTrue(data.stream().anyMatch(e -> {
            return e.getReferenceName().equals("test")
                    && EcoreUtil.equals(e.getSource(), create.fetchOfComponent("TestComponent"))
                    && EcoreUtil.equals(e.getDataType(), create.fetchOfCompositeDataType("TestDataType"));
        }));

        assertTrue(data.stream().anyMatch(e -> {
            return EcoreUtil.equals(e.getSource(), create.fetchOfSignature("test"))
                    && EcoreUtil.equals(e.getDataType(), create.fetchOfDataType(Primitive.INTEGER));
        }));

    }

    @Test
    void testExtractionSEFFParametersReturnValue() {

        repo.addToRepository(
                create.newCompositeDataType().withName("TestDataType").withInnerDeclaration("Test", Primitive.STRING));
        var operationSignature = create.newOperationSignature().withName("test")
                .withParameter("test", create.fetchOfDataType("TestDataType"), ParameterModifier.NONE)
                .withReturnType(create.fetchOfDataType(Primitive.INTEGER));
        var repository = repo
                .addToRepository(
                        create.newOperationInterface().withName("Test").withOperationSignature(operationSignature))
                .addToRepository(create.newBasicComponent().withName("TestComponent")
                        .withServiceEffectSpecification(create.newSeff().onSignature(create.fetchOfSignature("test")))
                        .provides(create.fetchOfOperationInterface("Test")))
                .createRepositoryNow();

        var component = create.fetchOfBasicComponent("TestComponent");
        var data = DataHandler
                .getData((ResourceDemandingSEFF) component.getServiceEffectSpecifications__BasicComponent().get(0));

        assertEquals(2, data.size());

        assertTrue(data.stream().anyMatch(e -> {
            return e.getReferenceName().equals("test")
                    && EcoreUtil.equals(e.getSource(), create.fetchOfComponent("TestComponent"))
                    && EcoreUtil.equals(e.getDataType(), create.fetchOfCompositeDataType("TestDataType"));
        }));

        assertTrue(data.stream().anyMatch(e -> {
            return EcoreUtil.equals(e.getSource(), create.fetchOfSignature("test"))
                    && EcoreUtil.equals(e.getDataType(), create.fetchOfDataType(Primitive.INTEGER));
        }));

    }

    @Test
    void testExtractionSEFFExternalCallParametersReturnValue() {

        repo.addToRepository(
                create.newCompositeDataType().withName("TestDataType").withInnerDeclaration("Test", Primitive.STRING));
        var operationSignature = create.newOperationSignature().withName("test")
                .withParameter("test", create.fetchOfDataType("TestDataType"), ParameterModifier.NONE)
                .withReturnType(create.fetchOfDataType(Primitive.INTEGER));

        var secretOperation = create.newOperationSignature().withName("secret")
                .withReturnType(create.fetchOfDataType(Primitive.STRING));

        repo.addToRepository(create.newOperationInterface().withName("Test").withOperationSignature(operationSignature))
                .addToRepository(
                        create.newOperationInterface().withName("Secret").withOperationSignature(secretOperation));

        var seff = create.newSeff().onSignature(create.fetchOfSignature("test")).withSeffBehaviour().withStartAction()
                .followedBy().externalCallAction().withCalledService(create.fetchOfOperationSignature("secret"))
                .followedBy().stopAction().createBehaviourNow();

        repo.addToRepository(
                create.newBasicComponent().withName("TestComponent").provides(create.fetchOfOperationInterface("Test"))
                        .requires(create.fetchOfOperationInterface("Secret")).withServiceEffectSpecification(seff))
                .createRepositoryNow();

        var component = create.fetchOfBasicComponent("TestComponent");
        var data = DataHandler
                .getData((ResourceDemandingSEFF) component.getServiceEffectSpecifications__BasicComponent().get(0));

        assertEquals(3, data.size());

        assertTrue(data.stream().anyMatch(e -> {
            return e.getReferenceName().equals("test")
                    && EcoreUtil.equals(e.getSource(), create.fetchOfComponent("TestComponent"))
                    && EcoreUtil.equals(e.getDataType(), create.fetchOfCompositeDataType("TestDataType"));
        }));

        assertTrue(data.stream().anyMatch(e -> {
            return EcoreUtil.equals(e.getSource(), create.fetchOfSignature("test"))
                    && EcoreUtil.equals(e.getDataType(), create.fetchOfDataType(Primitive.INTEGER));
        }));

        assertTrue(data.stream().anyMatch(e -> {
            return EcoreUtil.equals(e.getSource(), create.fetchOfSignature("secret"))
                    && EcoreUtil.equals(e.getDataType(), create.fetchOfDataType(Primitive.STRING));
        }));

    }

    @Test
    void testExtractionExternalCallParametersReturnValue() {

        repo.addToRepository(
                create.newCompositeDataType().withName("TestDataType").withInnerDeclaration("Test", Primitive.STRING));
        var operationSignature = create.newOperationSignature().withName("test")
                .withParameter("test", create.fetchOfDataType("TestDataType"), ParameterModifier.NONE)
                .withReturnType(create.fetchOfDataType(Primitive.INTEGER));

        var secretOperation = create.newOperationSignature().withName("secret")
                .withReturnType(create.fetchOfDataType(Primitive.STRING));

        repo.addToRepository(create.newOperationInterface().withName("Test").withOperationSignature(operationSignature))
                .addToRepository(
                        create.newOperationInterface().withName("Secret").withOperationSignature(secretOperation));

        var seff = create.newSeff().onSignature(create.fetchOfSignature("test")).withSeffBehaviour().withStartAction()
                .followedBy().externalCallAction().withCalledService(create.fetchOfOperationSignature("secret"))
                .followedBy().stopAction().createBehaviourNow();

        repo.addToRepository(
                create.newBasicComponent().withName("TestComponent").provides(create.fetchOfOperationInterface("Test"))
                        .requires(create.fetchOfOperationInterface("Secret")).withServiceEffectSpecification(seff))
                .createRepositoryNow();

        var component = create.fetchOfBasicComponent("TestComponent");
        var data = DataHandler.getData(component);

        assertEquals(3, data.size());

        assertTrue(data.stream().anyMatch(e -> {
            return e.getReferenceName().equals("test")
                    && EcoreUtil.equals(e.getSource(), create.fetchOfComponent("TestComponent"))
                    && EcoreUtil.equals(e.getDataType(), create.fetchOfCompositeDataType("TestDataType"));
        }));

        assertTrue(data.stream().anyMatch(e -> {
            return EcoreUtil.equals(e.getSource(), create.fetchOfSignature("test"))
                    && EcoreUtil.equals(e.getDataType(), create.fetchOfDataType(Primitive.INTEGER));
        }));

        assertTrue(data.stream().anyMatch(e -> {
            return EcoreUtil.equals(e.getSource(), create.fetchOfSignature("secret"))
                    && EcoreUtil.equals(e.getDataType(), create.fetchOfDataType(Primitive.STRING));
        }));

    }

}
