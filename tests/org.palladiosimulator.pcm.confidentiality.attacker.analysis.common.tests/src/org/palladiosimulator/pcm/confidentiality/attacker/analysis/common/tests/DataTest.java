package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.generator.fluent.repository.api.Repo;
import org.palladiosimulator.generator.fluent.repository.factory.FluentRepositoryFactory;
import org.palladiosimulator.generator.fluent.repository.structure.internals.Primitive;
import org.palladiosimulator.generator.fluent.system.factory.FluentSystemFactory;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandler;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceSpecification;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.StructureFactory;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.repository.BasicComponent;
import org.palladiosimulator.pcm.repository.OperationProvidedRole;
import org.palladiosimulator.pcm.repository.OperationRequiredRole;
import org.palladiosimulator.pcm.repository.ParameterModifier;
import org.palladiosimulator.pcm.seff.ResourceDemandingSEFF;

class DataTest {

    private Repo repo;
    private FluentRepositoryFactory repositoryFactory;
    private FluentSystemFactory systemFactory;

    @BeforeEach
    void prepare() {
        this.repositoryFactory = new FluentRepositoryFactory();
        this.systemFactory = new FluentSystemFactory();
        this.repo = this.repositoryFactory.newRepository();
        this.systemFactory.newSystem();
    }

    @Test
    void testExtractionRepositoryParameters() {

        this.repo.addToRepository(this.repositoryFactory.newCompositeDataType().withName("TestDataType")
                .withInnerDeclaration("Test", Primitive.STRING));
        final var operationSignature = this.repositoryFactory.newOperationSignature().withName("test")
                .withParameter("test", this.repositoryFactory.fetchOfDataType("TestDataType"), ParameterModifier.NONE);
        this.repo
                .addToRepository(this.repositoryFactory.newOperationInterface().withName("Test")
                        .withOperationSignature(operationSignature))
                .addToRepository(this.repositoryFactory.newBasicComponent().withName("TestComponent")
                        .withServiceEffectSpecification(this.repositoryFactory.newSeff()
                                .onSignature(this.repositoryFactory.fetchOfSignature("test")))
                        .provides(this.repositoryFactory.fetchOfOperationInterface("Test")))
                .createRepositoryNow();

        final var component = this.systemFactory.newAssemblyContext()
                .withEncapsulatedComponent(this.repositoryFactory.fetchOfBasicComponent("TestComponent")).build();
        final var data = DataHandler.getData(component);

        assertEquals(1, data.size());

        assertTrue(data.stream().anyMatch(
                e -> (e.getReferenceName().equals("test") && EcoreUtil.equals(e.getSource(), component) && EcoreUtil
                        .equals(e.getDataType(), this.repositoryFactory.fetchOfCompositeDataType("TestDataType")))));

    }

    @Test
    void testExtractionRepositoryReturnValuesDefault() {

        this.repo.addToRepository(this.repositoryFactory.newCompositeDataType().withName("TestDataType")
                .withInnerDeclaration("Test", Primitive.STRING));
        final var operationSignature = this.repositoryFactory.newOperationSignature().withName("test")
                .withReturnType(Primitive.BOOLEAN);
        this.repo
                .addToRepository(this.repositoryFactory.newOperationInterface().withName("Test")
                        .withOperationSignature(operationSignature))
                .addToRepository(this.repositoryFactory.newBasicComponent().withName("TestComponent")
                        .withServiceEffectSpecification(this.repositoryFactory.newSeff()
                                .onSignature(this.repositoryFactory.fetchOfSignature("test")))
                        .provides(this.repositoryFactory.fetchOfOperationInterface("Test")))
                .createRepositoryNow();

        final var component = this.systemFactory.newAssemblyContext()
                .withEncapsulatedComponent(this.repositoryFactory.fetchOfBasicComponent("TestComponent")).build();
        final var data = DataHandler.getData(component);

        assertEquals(1, data.size());

        assertTrue(data.stream().anyMatch(e -> (EcoreUtil.equals(e.getSource(), component)
                && EcoreUtil.equals(e.getDataType(), this.repositoryFactory.fetchOfDataType(Primitive.BOOLEAN)))));

    }

    @Test
    void testExtractionRepositoryReturnValuesComplex() {

        this.repo.addToRepository(this.repositoryFactory.newCompositeDataType().withName("TestDataType")
                .withInnerDeclaration("Test", Primitive.STRING));
        final var operationSignature = this.repositoryFactory.newOperationSignature().withName("test")
                .withReturnType(this.repositoryFactory.fetchOfDataType("TestDataType"));
        this.repo
                .addToRepository(this.repositoryFactory.newOperationInterface().withName("Test")
                        .withOperationSignature(operationSignature))
                .addToRepository(this.repositoryFactory.newBasicComponent().withName("TestComponent")
                        .withServiceEffectSpecification(this.repositoryFactory.newSeff()
                                .onSignature(this.repositoryFactory.fetchOfSignature("test")))
                        .provides(this.repositoryFactory.fetchOfOperationInterface("Test")))
                .createRepositoryNow();

        final var component = this.systemFactory.newAssemblyContext()
                .withEncapsulatedComponent(this.repositoryFactory.fetchOfBasicComponent("TestComponent")).build();
        final var data = DataHandler.getData(component);

        assertEquals(1, data.size());

        assertTrue(data.stream().anyMatch(e -> (EcoreUtil.equals(e.getSource(), component)
                && EcoreUtil.equals(e.getDataType(), this.repositoryFactory.fetchOfDataType("TestDataType")))));

    }

    @Test
    void testExtractionRepositoryReturnValuesInteger() {

        this.repo.addToRepository(this.repositoryFactory.newCompositeDataType().withName("TestDataType")
                .withInnerDeclaration("Test", Primitive.STRING));
        final var operationSignature = this.repositoryFactory.newOperationSignature().withName("test")
                .withReturnType(this.repositoryFactory.fetchOfDataType(Primitive.INTEGER));
        this.repo
                .addToRepository(this.repositoryFactory.newOperationInterface().withName("Test")
                        .withOperationSignature(operationSignature))
                .addToRepository(this.repositoryFactory.newBasicComponent().withName("TestComponent")
                        .withServiceEffectSpecification(this.repositoryFactory.newSeff()
                                .onSignature(this.repositoryFactory.fetchOfSignature("test")))
                        .provides(this.repositoryFactory.fetchOfOperationInterface("Test")))
                .createRepositoryNow();

        final var component = this.systemFactory.newAssemblyContext()
                .withEncapsulatedComponent(this.repositoryFactory.fetchOfBasicComponent("TestComponent")).build();
        final var data = DataHandler.getData(component);

        assertEquals(1, data.size());

        assertTrue(data.stream().anyMatch(e -> (EcoreUtil.equals(e.getSource(), component)
                && EcoreUtil.equals(e.getDataType(), this.repositoryFactory.fetchOfDataType(Primitive.INTEGER)))));

    }

    @Test
    void testExtractionRepositoryParametersReturnValue() {

        this.repo.addToRepository(this.repositoryFactory.newCompositeDataType().withName("TestDataType")
                .withInnerDeclaration("Test", Primitive.STRING));
        final var operationSignature = this.repositoryFactory.newOperationSignature().withName("test")
                .withParameter("test", this.repositoryFactory.fetchOfDataType("TestDataType"), ParameterModifier.NONE)
                .withReturnType(this.repositoryFactory.fetchOfDataType(Primitive.INTEGER));
        this.repo
                .addToRepository(this.repositoryFactory.newOperationInterface().withName("Test")
                        .withOperationSignature(operationSignature))
                .addToRepository(this.repositoryFactory.newBasicComponent().withName("TestComponent")
                        .withServiceEffectSpecification(this.repositoryFactory.newSeff()
                                .onSignature(this.repositoryFactory.fetchOfSignature("test")))
                        .provides(this.repositoryFactory.fetchOfOperationInterface("Test")))
                .createRepositoryNow();

        final var component = this.systemFactory.newAssemblyContext()
                .withEncapsulatedComponent(this.repositoryFactory.fetchOfBasicComponent("TestComponent")).build();
        final var data = DataHandler.getData(component);

        assertEquals(2, data.size());

        assertTrue(data.stream().anyMatch(
                e -> ("test".equals(e.getReferenceName()) && EcoreUtil.equals(e.getSource(), component) && EcoreUtil
                        .equals(e.getDataType(), this.repositoryFactory.fetchOfCompositeDataType("TestDataType")))));

        assertTrue(data.stream().anyMatch(e -> (EcoreUtil.equals(e.getSource(), component)
                && EcoreUtil.equals(e.getDataType(), this.repositoryFactory.fetchOfDataType(Primitive.INTEGER)))));

    }

    @Test
    void testExtractionSEFFParametersReturnValue() {

        this.repo.addToRepository(this.repositoryFactory.newCompositeDataType().withName("TestDataType")
                .withInnerDeclaration("Test", Primitive.STRING));
        final var operationSignature = this.repositoryFactory.newOperationSignature().withName("test")
                .withParameter("test", this.repositoryFactory.fetchOfDataType("TestDataType"), ParameterModifier.NONE)
                .withReturnType(this.repositoryFactory.fetchOfDataType(Primitive.INTEGER));
        this.repo
                .addToRepository(this.repositoryFactory.newOperationInterface().withName("Test")
                        .withOperationSignature(operationSignature))
                .addToRepository(this.repositoryFactory.newBasicComponent().withName("TestComponent")
                        .withServiceEffectSpecification(this.repositoryFactory.newSeff()
                                .onSignature(this.repositoryFactory.fetchOfSignature("test")))
                        .provides(this.repositoryFactory.fetchOfOperationInterface("Test")))
                .createRepositoryNow();

        final var component = this.repositoryFactory.fetchOfBasicComponent("TestComponent");
        var serviceRestriction = createServiceRestrictions(component);
        final var data = DataHandler.getData(serviceRestriction);

        assertEquals(2, data.size());

        assertTrue(data.stream()
                .anyMatch(e -> ("test".equals(e.getReferenceName())
                        && EcoreUtil.equals(e.getSource(), serviceRestriction) && EcoreUtil.equals(e.getDataType(),
                                this.repositoryFactory.fetchOfCompositeDataType("TestDataType")))));

        assertTrue(data.stream().anyMatch(e -> (EcoreUtil.equals(e.getSource(), serviceRestriction)
                && EcoreUtil.equals(e.getDataType(), this.repositoryFactory.fetchOfDataType(Primitive.INTEGER)))));

    }

    // Disabled because it needs adaptation to a full system definition
    @Disabled
    @Test
    void testExtractionSEFFExternalCallParametersReturnValue() {

        this.repo.addToRepository(this.repositoryFactory.newCompositeDataType().withName("TestDataType")
                .withInnerDeclaration("Test", Primitive.STRING));
        final var operationSignature = this.repositoryFactory.newOperationSignature().withName("test")
                .withParameter("test", this.repositoryFactory.fetchOfDataType("TestDataType"), ParameterModifier.NONE)
                .withReturnType(this.repositoryFactory.fetchOfDataType(Primitive.INTEGER));

        final var secretOperation = this.repositoryFactory.newOperationSignature().withName("secret")
                .withReturnType(this.repositoryFactory.fetchOfDataType(Primitive.STRING));

        this.repo
                .addToRepository(this.repositoryFactory.newOperationInterface().withName("Test")
                        .withOperationSignature(operationSignature))
                .addToRepository(this.repositoryFactory.newOperationInterface().withName("Secret")
                        .withOperationSignature(secretOperation));

        final var seff = this.repositoryFactory.newSeff().onSignature(this.repositoryFactory.fetchOfSignature("test"))
                .withSeffBehaviour().withStartAction().followedBy().externalCallAction()
                .withCalledService(this.repositoryFactory.fetchOfOperationSignature("secret")).followedBy().stopAction()
                .createBehaviourNow();
        var secretSeff = this.repositoryFactory.newSeff().onSignature(this.repositoryFactory.fetchOfSignature("secret"))
                .withSeffBehaviour().withStartAction().followedBy().stopAction().createBehaviourNow();

        var localRepo = this.repo
                .addToRepository(this.repositoryFactory.newBasicComponent().withName("TestComponent")
                        .provides(this.repositoryFactory.fetchOfOperationInterface("Test"))
                        .requires(this.repositoryFactory.fetchOfOperationInterface("Secret"))
                        .withServiceEffectSpecification(seff))
                .addToRepository(this.repositoryFactory.newBasicComponent().withName("SecretProvider")
                        .provides(this.repositoryFactory.fetchOfOperationInterface("Secret"))
                        .withServiceEffectSpecification(secretSeff))
                .createRepositoryNow();



        final var component = this.repositoryFactory.fetchOfBasicComponent("TestComponent");


        var system = this.systemFactory.newSystem().addRepository(localRepo).addToSystem(this.systemFactory.newAssemblyContext()
                .withEncapsulatedComponent(this.repositoryFactory.fetchOfComponent("SecretProvider")).withName("AssemblySecretProvider")).addToSystem(
                        this.systemFactory.newAssemblyContext().withEncapsulatedComponent(component).withName("AssemblyComponent")).addToSystem(this.systemFactory.newAssemblyConnector().withProvidingAssemblyContext("AssemblySecretProvider")
                                .withOperationProvidedRole((OperationProvidedRole) this.repositoryFactory
                                        .fetchOfBasicComponent("SecretProvider").getProvidedRoles_InterfaceProvidingEntity().get(0)).withRequiringAssemblyContext("AssemblyComponent")
                                .withOperationRequiredRole(
                                        (OperationRequiredRole) component.getRequiredRoles_InterfaceRequiringEntity().get(0))).createSystemNow();
        var assemblyContext = system.getAssemblyContexts__ComposedStructure().stream()
                .filter(e -> e.getEntityName().equals("AssemblySecretProvider")).findFirst();
        if(assemblyContext.isEmpty()) {
            fail();
        }
        var serviceRestriction = createServiceRestrictions(component, assemblyContext.get());

        final var data = DataHandler.getData(serviceRestriction);

        assertEquals(3, data.size());

        assertTrue(data.stream()
                .anyMatch(e -> ("test".equals(e.getReferenceName())
                        && EcoreUtil.equals(e.getSource(), serviceRestriction) && EcoreUtil.equals(e.getDataType(),
                                this.repositoryFactory.fetchOfCompositeDataType("TestDataType")))));

        assertTrue(data.stream()
                .anyMatch(e -> (EcoreUtil.equals(e.getMethod(), this.repositoryFactory.fetchOfSignature("test"))
                        && EcoreUtil.equals(e.getSource(), serviceRestriction) && EcoreUtil.equals(e.getDataType(),
                                this.repositoryFactory.fetchOfDataType(Primitive.INTEGER)))));

        assertTrue(data.stream()
                .anyMatch(e -> (EcoreUtil.equals(e.getMethod(), this.repositoryFactory.fetchOfSignature("secret"))
                        && EcoreUtil.equals(e.getSource(), serviceRestriction) && EcoreUtil.equals(e.getDataType(),
                                this.repositoryFactory.fetchOfDataType(Primitive.STRING)))));

    }

    private ServiceSpecification createServiceRestrictions(final BasicComponent component, AssemblyContext context) {
        var serviceRestriction = StructureFactory.eINSTANCE.createServiceSpecification();
        serviceRestriction.setAssemblycontext(context);
        var seff = (ResourceDemandingSEFF) component.getServiceEffectSpecifications__BasicComponent().get(0);
        serviceRestriction.setService(seff);
        serviceRestriction.setSignature(seff.getDescribedService__SEFF());
        return serviceRestriction;
    }

    private ServiceSpecification createServiceRestrictions(final BasicComponent component) {
        return createServiceRestrictions(component,
                this.systemFactory.newAssemblyContext().withEncapsulatedComponent(component).build());
    }

    @Disabled
    @Test
    void testExtractionExternalCallParametersReturnValue() {

        this.repo.addToRepository(this.repositoryFactory.newCompositeDataType().withName("TestDataType")
                .withInnerDeclaration("Test", Primitive.STRING));
        final var operationSignature = this.repositoryFactory.newOperationSignature().withName("test")
                .withParameter("test", this.repositoryFactory.fetchOfDataType("TestDataType"), ParameterModifier.NONE)
                .withReturnType(this.repositoryFactory.fetchOfDataType(Primitive.INTEGER));

        final var secretOperation = this.repositoryFactory.newOperationSignature().withName("secret")
                .withReturnType(this.repositoryFactory.fetchOfDataType(Primitive.STRING));

        this.repo
                .addToRepository(this.repositoryFactory.newOperationInterface().withName("Test")
                        .withOperationSignature(operationSignature))
                .addToRepository(this.repositoryFactory.newOperationInterface().withName("Secret")
                        .withOperationSignature(secretOperation));

        final var seff = this.repositoryFactory.newSeff().onSignature(this.repositoryFactory.fetchOfSignature("test"))
                .withSeffBehaviour().withStartAction().followedBy().externalCallAction()
                .withCalledService(this.repositoryFactory.fetchOfOperationSignature("secret")).followedBy().stopAction()
                .createBehaviourNow();

        this.repo.addToRepository(this.repositoryFactory.newBasicComponent().withName("TestComponent")
                .provides(this.repositoryFactory.fetchOfOperationInterface("Test"))
                .requires(this.repositoryFactory.fetchOfOperationInterface("Secret"))
                .withServiceEffectSpecification(seff)).createRepositoryNow();

        final var component = this.systemFactory.newAssemblyContext()
                .withEncapsulatedComponent(this.repositoryFactory.fetchOfBasicComponent("TestComponent")).build();
        final var data = DataHandler.getData(component);

//FIXME: needs adaption for required
        assertEquals(3, data.size());

        assertTrue(data.stream().anyMatch(
                e -> ("test".equals(e.getReferenceName()) && EcoreUtil.equals(e.getSource(), component) && EcoreUtil
                        .equals(e.getDataType(), this.repositoryFactory.fetchOfCompositeDataType("TestDataType")))));

        assertTrue(data.stream()
                .anyMatch(e -> (EcoreUtil.equals(e.getMethod(), this.repositoryFactory.fetchOfSignature("test"))
                        && EcoreUtil.equals(e.getSource(), component) && EcoreUtil.equals(e.getDataType(),
                                this.repositoryFactory.fetchOfDataType(Primitive.INTEGER)))));

        assertTrue(data.stream()
                .anyMatch(e -> (EcoreUtil.equals(e.getMethod(), this.repositoryFactory.fetchOfSignature("secret"))
                        && EcoreUtil.equals(e.getSource(), component) && EcoreUtil.equals(e.getDataType(),
                                this.repositoryFactory.fetchOfDataType(Primitive.STRING)))));

    }

}
