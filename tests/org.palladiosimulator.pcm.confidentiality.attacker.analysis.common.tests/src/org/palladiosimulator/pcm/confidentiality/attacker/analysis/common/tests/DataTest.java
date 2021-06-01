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

class DataTest {

    private Repo repo;
    private FluentRepositoryFactory create;

    @BeforeEach
    void prepare() {
        this.create = new FluentRepositoryFactory();
        this.repo = this.create.newRepository();
    }

    @Test
    void testExtractionRepositoryParameters() {

        this.repo.addToRepository(this.create.newCompositeDataType().withName("TestDataType")
                .withInnerDeclaration("Test", Primitive.STRING));
        final var operationSignature = this.create.newOperationSignature().withName("test").withParameter("test",
                this.create.fetchOfDataType("TestDataType"), ParameterModifier.NONE);
        this.repo
                .addToRepository(
                        this.create.newOperationInterface().withName("Test").withOperationSignature(operationSignature))
                .addToRepository(this.create.newBasicComponent().withName("TestComponent")
                        .withServiceEffectSpecification(
                                this.create.newSeff().onSignature(this.create.fetchOfSignature("test")))
                        .provides(this.create.fetchOfOperationInterface("Test")))
                .createRepositoryNow();

        final var component = this.create.fetchOfBasicComponent("TestComponent");
        final var data = DataHandler.getData(component);

        assertEquals(1, data.size());

        assertTrue(data.stream().anyMatch(e -> {
            return e.getReferenceName().equals("test")
                    && EcoreUtil.equals(e.getSource(), this.create.fetchOfComponent("TestComponent"))
                    && EcoreUtil.equals(e.getDataType(), this.create.fetchOfCompositeDataType("TestDataType"));
        }));

    }

    @Test
    void testExtractionRepositoryReturnValuesDefault() {

        this.repo.addToRepository(this.create.newCompositeDataType().withName("TestDataType")
                .withInnerDeclaration("Test", Primitive.STRING));
        final var operationSignature = this.create.newOperationSignature().withName("test")
                .withReturnType(Primitive.BOOLEAN);
        this.repo
                .addToRepository(
                        this.create.newOperationInterface().withName("Test").withOperationSignature(operationSignature))
                .addToRepository(this.create.newBasicComponent().withName("TestComponent")
                        .withServiceEffectSpecification(
                                this.create.newSeff().onSignature(this.create.fetchOfSignature("test")))
                        .provides(this.create.fetchOfOperationInterface("Test")))
                .createRepositoryNow();

        final var component = this.create.fetchOfBasicComponent("TestComponent");
        final var data = DataHandler.getData(component);

        assertEquals(1, data.size());

        assertTrue(data.stream().anyMatch(e -> {
            return EcoreUtil.equals(e.getSource(), this.create.fetchOfSignature("test"))
                    && EcoreUtil.equals(e.getDataType(), this.create.fetchOfDataType(Primitive.BOOLEAN));
        }));

    }

    @Test
    void testExtractionRepositoryReturnValuesComplex() {

        this.repo.addToRepository(this.create.newCompositeDataType().withName("TestDataType")
                .withInnerDeclaration("Test", Primitive.STRING));
        final var operationSignature = this.create.newOperationSignature().withName("test")
                .withReturnType(this.create.fetchOfDataType("TestDataType"));
        this.repo
                .addToRepository(
                        this.create.newOperationInterface().withName("Test").withOperationSignature(operationSignature))
                .addToRepository(this.create.newBasicComponent().withName("TestComponent")
                        .withServiceEffectSpecification(
                                this.create.newSeff().onSignature(this.create.fetchOfSignature("test")))
                        .provides(this.create.fetchOfOperationInterface("Test")))
                .createRepositoryNow();

        final var component = this.create.fetchOfBasicComponent("TestComponent");
        final var data = DataHandler.getData(component);

        assertEquals(1, data.size());

        assertTrue(data.stream().anyMatch(e -> {
            return EcoreUtil.equals(e.getSource(), this.create.fetchOfSignature("test"))
                    && EcoreUtil.equals(e.getDataType(), this.create.fetchOfDataType("TestDataType"));
        }));

    }

    @Test
    void testExtractionRepositoryReturnValuesInteger() {

        this.repo.addToRepository(this.create.newCompositeDataType().withName("TestDataType")
                .withInnerDeclaration("Test", Primitive.STRING));
        final var operationSignature = this.create.newOperationSignature().withName("test")
                .withReturnType(this.create.fetchOfDataType(Primitive.INTEGER));
        this.repo
                .addToRepository(
                        this.create.newOperationInterface().withName("Test").withOperationSignature(operationSignature))
                .addToRepository(this.create.newBasicComponent().withName("TestComponent")
                        .withServiceEffectSpecification(
                                this.create.newSeff().onSignature(this.create.fetchOfSignature("test")))
                        .provides(this.create.fetchOfOperationInterface("Test")))
                .createRepositoryNow();

        final var component = this.create.fetchOfBasicComponent("TestComponent");
        final var data = DataHandler.getData(component);

        assertEquals(1, data.size());

        assertTrue(data.stream().anyMatch(e -> {
            return EcoreUtil.equals(e.getSource(), this.create.fetchOfSignature("test"))
                    && EcoreUtil.equals(e.getDataType(), this.create.fetchOfDataType(Primitive.INTEGER));
        }));

    }

    @Test
    void testExtractionRepositoryParametersReturnValue() {

        this.repo.addToRepository(this.create.newCompositeDataType().withName("TestDataType")
                .withInnerDeclaration("Test", Primitive.STRING));
        final var operationSignature = this.create.newOperationSignature().withName("test")
                .withParameter("test", this.create.fetchOfDataType("TestDataType"), ParameterModifier.NONE)
                .withReturnType(this.create.fetchOfDataType(Primitive.INTEGER));
        this.repo
                .addToRepository(
                        this.create.newOperationInterface().withName("Test").withOperationSignature(operationSignature))
                .addToRepository(this.create.newBasicComponent().withName("TestComponent")
                        .withServiceEffectSpecification(
                                this.create.newSeff().onSignature(this.create.fetchOfSignature("test")))
                        .provides(this.create.fetchOfOperationInterface("Test")))
                .createRepositoryNow();

        final var component = this.create.fetchOfBasicComponent("TestComponent");
        final var data = DataHandler.getData(component);

        assertEquals(2, data.size());

        assertTrue(data.stream().anyMatch(e -> {
            return e.getReferenceName().equals("test")
                    && EcoreUtil.equals(e.getSource(), this.create.fetchOfComponent("TestComponent"))
                    && EcoreUtil.equals(e.getDataType(), this.create.fetchOfCompositeDataType("TestDataType"));
        }));

        assertTrue(data.stream().anyMatch(e -> {
            return EcoreUtil.equals(e.getSource(), this.create.fetchOfSignature("test"))
                    && EcoreUtil.equals(e.getDataType(), this.create.fetchOfDataType(Primitive.INTEGER));
        }));

    }

    @Test
    void testExtractionSEFFParametersReturnValue() {

        this.repo.addToRepository(this.create.newCompositeDataType().withName("TestDataType")
                .withInnerDeclaration("Test", Primitive.STRING));
        final var operationSignature = this.create.newOperationSignature().withName("test")
                .withParameter("test", this.create.fetchOfDataType("TestDataType"), ParameterModifier.NONE)
                .withReturnType(this.create.fetchOfDataType(Primitive.INTEGER));
        this.repo
                .addToRepository(
                        this.create.newOperationInterface().withName("Test").withOperationSignature(operationSignature))
                .addToRepository(this.create.newBasicComponent().withName("TestComponent")
                        .withServiceEffectSpecification(
                                this.create.newSeff().onSignature(this.create.fetchOfSignature("test")))
                        .provides(this.create.fetchOfOperationInterface("Test")))
                .createRepositoryNow();

        final var component = this.create.fetchOfBasicComponent("TestComponent");
        final var data = DataHandler
                .getData((ResourceDemandingSEFF) component.getServiceEffectSpecifications__BasicComponent().get(0));

        assertEquals(2, data.size());

        assertTrue(data.stream().anyMatch(e -> {
            return e.getReferenceName().equals("test")
                    && EcoreUtil.equals(e.getSource(), this.create.fetchOfComponent("TestComponent"))
                    && EcoreUtil.equals(e.getDataType(), this.create.fetchOfCompositeDataType("TestDataType"));
        }));

        assertTrue(data.stream().anyMatch(e -> {
            return EcoreUtil.equals(e.getSource(), this.create.fetchOfSignature("test"))
                    && EcoreUtil.equals(e.getDataType(), this.create.fetchOfDataType(Primitive.INTEGER));
        }));

    }

    @Test
    void testExtractionSEFFExternalCallParametersReturnValue() {

        this.repo.addToRepository(this.create.newCompositeDataType().withName("TestDataType")
                .withInnerDeclaration("Test", Primitive.STRING));
        final var operationSignature = this.create.newOperationSignature().withName("test")
                .withParameter("test", this.create.fetchOfDataType("TestDataType"), ParameterModifier.NONE)
                .withReturnType(this.create.fetchOfDataType(Primitive.INTEGER));

        final var secretOperation = this.create.newOperationSignature().withName("secret")
                .withReturnType(this.create.fetchOfDataType(Primitive.STRING));

        this.repo
                .addToRepository(
                        this.create.newOperationInterface().withName("Test").withOperationSignature(operationSignature))
                .addToRepository(
                        this.create.newOperationInterface().withName("Secret").withOperationSignature(secretOperation));

        final var seff = this.create.newSeff().onSignature(this.create.fetchOfSignature("test")).withSeffBehaviour()
                .withStartAction().followedBy().externalCallAction()
                .withCalledService(this.create.fetchOfOperationSignature("secret")).followedBy().stopAction()
                .createBehaviourNow();

        this.repo
                .addToRepository(this.create.newBasicComponent().withName("TestComponent")
                        .provides(this.create.fetchOfOperationInterface("Test"))
                        .requires(this.create.fetchOfOperationInterface("Secret")).withServiceEffectSpecification(seff))
                .createRepositoryNow();

        final var component = this.create.fetchOfBasicComponent("TestComponent");
        final var data = DataHandler
                .getData((ResourceDemandingSEFF) component.getServiceEffectSpecifications__BasicComponent().get(0));

        assertEquals(3, data.size());

        assertTrue(data.stream().anyMatch(e -> {
            return e.getReferenceName().equals("test")
                    && EcoreUtil.equals(e.getSource(), this.create.fetchOfComponent("TestComponent"))
                    && EcoreUtil.equals(e.getDataType(), this.create.fetchOfCompositeDataType("TestDataType"));
        }));

        assertTrue(data.stream().anyMatch(e -> {
            return EcoreUtil.equals(e.getSource(), this.create.fetchOfSignature("test"))
                    && EcoreUtil.equals(e.getDataType(), this.create.fetchOfDataType(Primitive.INTEGER));
        }));

        assertTrue(data.stream().anyMatch(e -> {
            return EcoreUtil.equals(e.getSource(), this.create.fetchOfSignature("secret"))
                    && EcoreUtil.equals(e.getDataType(), this.create.fetchOfDataType(Primitive.STRING));
        }));

    }

    @Test
    void testExtractionExternalCallParametersReturnValue() {

        this.repo.addToRepository(this.create.newCompositeDataType().withName("TestDataType")
                .withInnerDeclaration("Test", Primitive.STRING));
        final var operationSignature = this.create.newOperationSignature().withName("test")
                .withParameter("test", this.create.fetchOfDataType("TestDataType"), ParameterModifier.NONE)
                .withReturnType(this.create.fetchOfDataType(Primitive.INTEGER));

        final var secretOperation = this.create.newOperationSignature().withName("secret")
                .withReturnType(this.create.fetchOfDataType(Primitive.STRING));

        this.repo
                .addToRepository(
                        this.create.newOperationInterface().withName("Test").withOperationSignature(operationSignature))
                .addToRepository(
                        this.create.newOperationInterface().withName("Secret").withOperationSignature(secretOperation));

        final var seff = this.create.newSeff().onSignature(this.create.fetchOfSignature("test")).withSeffBehaviour()
                .withStartAction().followedBy().externalCallAction()
                .withCalledService(this.create.fetchOfOperationSignature("secret")).followedBy().stopAction()
                .createBehaviourNow();

        this.repo
                .addToRepository(this.create.newBasicComponent().withName("TestComponent")
                        .provides(this.create.fetchOfOperationInterface("Test"))
                        .requires(this.create.fetchOfOperationInterface("Secret")).withServiceEffectSpecification(seff))
                .createRepositoryNow();

        final var component = this.create.fetchOfBasicComponent("TestComponent");
        final var data = DataHandler.getData(component);

        assertEquals(3, data.size());

        assertTrue(data.stream().anyMatch(e -> {
            return e.getReferenceName().equals("test")
                    && EcoreUtil.equals(e.getSource(), this.create.fetchOfComponent("TestComponent"))
                    && EcoreUtil.equals(e.getDataType(), this.create.fetchOfCompositeDataType("TestDataType"));
        }));

        assertTrue(data.stream().anyMatch(e -> {
            return EcoreUtil.equals(e.getSource(), this.create.fetchOfSignature("test"))
                    && EcoreUtil.equals(e.getDataType(), this.create.fetchOfDataType(Primitive.INTEGER));
        }));

        assertTrue(data.stream().anyMatch(e -> {
            return EcoreUtil.equals(e.getSource(), this.create.fetchOfSignature("secret"))
                    && EcoreUtil.equals(e.getDataType(), this.create.fetchOfDataType(Primitive.STRING));
        }));

    }

}
