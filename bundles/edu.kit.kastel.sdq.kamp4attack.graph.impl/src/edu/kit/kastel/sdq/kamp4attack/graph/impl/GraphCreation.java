package edu.kit.kastel.sdq.kamp4attack.graph.impl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.apache.log4j.Logger;
import org.eclipse.emf.ecore.EObject;
import org.osgi.service.component.annotations.Component;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.DatamodelAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.MethodSpecification;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceSpecification;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.repository.PrimitiveDataType;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import com.google.common.graph.MutableValueGraph;
import com.google.common.graph.ValueGraphBuilder;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationRepository;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ModifyEntity;
import edu.kit.kastel.sdq.kamp4attack.graph.api.AttackGraphCreation;
import edu.kit.kastel.sdq.kamp4attack.graph.impl.output.DotCreation;

@Component(service = AttackGraphCreation.class)
public class GraphCreation implements AttackGraphCreation {

    private final Logger logger = Logger.getLogger(GraphCreation.class);

    @Override
    public Optional<Path> createAttackGraph(final KAMP4attackModificationRepository modificationPartition) {
        if (modificationPartition.getChangePropagationSteps()
            .size() == 1) {

            final var change = modificationPartition.getChangePropagationSteps()
                .get(0);

            final MutableValueGraph<String, String> graph = ValueGraphBuilder.directed()
                .allowsSelfLoops(true)
                .build();

            this.fillGraph(graph, change.getCompromisedassembly());
            this.fillGraph(graph, change.getCompromisedresource());
            this.fillGraph(graph, change.getCompromisedlinkingresource());
            this.fillGraph(graph, change.getCompromisedservice());
            this.fillGraph(graph, change.getContextchange());
            this.fillGraph(graph, change.getCompromiseddata());
            final var dot = new DotCreation();
            final var dotString = dot.createOutputFormat(graph);

            try {
                final var file = Files.createTempFile("test", ".dot");

                Files.writeString(file.toAbsolutePath(), dotString);
                final var command = String.format("dot -Tpng %s", file.toAbsolutePath()
                    .toString());
                final var process = Runtime.getRuntime()
                    .exec(command);

                final var outputFile = Files.createTempFile("test", ".png");
                final var outputStream = Files.newOutputStream(outputFile.toAbsolutePath());
                process.getInputStream()
                    .transferTo(outputStream);

                final var errorStream = new ByteArrayOutputStream();
                process.getErrorStream()
                    .transferTo(errorStream);
                if (errorStream.size() != 0) {
                    this.logger.error(errorStream.toString());
                }
                return Optional.of(outputFile);
            } catch (final IOException e) {
                this.logger.error(e);
            }

        }
        return Optional.empty();

    }

    private void fillGraph(final MutableValueGraph<String, String> graph,
            final List<? extends ModifyEntity<? extends Entity>> change) {
        for (final var assembly : change) {
            final var node = assembly.getAffectedElement();
            final var source = this.getSource(assembly.getCausingElements());
            for (final var entity : source) {
                graph.putEdgeValue(entity, this.getString(node), this.getName(assembly.getCausingElements()));
            }
        }
    }

    private List<String> getSource(final List<EObject> list) {
        return list.stream()
            .filter(e -> (e instanceof ResourceContainer) || e instanceof AssemblyContext
                    || e instanceof LinkingResource || e instanceof MethodSpecification)
            .map(Entity.class::cast)
            .map(this::getString)
            .collect(Collectors.toList());
    }

    private List<Vulnerability> getVulnerabilites(final List<EObject> list) {
        return list.stream()
            .filter(Vulnerability.class::isInstance)
            .map(Vulnerability.class::cast)
            .collect(Collectors.toList());
    }

    private List<UsageSpecification> getCredentials(final List<EObject> list) {
        return list.stream()
            .filter(UsageSpecification.class::isInstance)
            .map(UsageSpecification.class::cast)
            .collect(Collectors.toList());
    }

    private String getName(final List<EObject> list) {
        final var vulnerabilitiesString = this.getVulnerabilites(list)
            .stream()
            .map(Entity::getEntityName)
            .collect(Collectors.joining(", "));
        final var credentials = this.getCredentials(list)
            .stream()
            .map(this::getString)
            .collect(Collectors.joining(", "));

        if (vulnerabilitiesString.isEmpty() && credentials.isEmpty()) {
            return "implicit";
        } else if (vulnerabilitiesString.isEmpty()) {
            return credentials;
        } else if (credentials.isEmpty()) {
            return vulnerabilitiesString;
        }
        return String.join(", ", vulnerabilitiesString, credentials);

    }

    private String getString(final Entity entity) {
        if (entity instanceof ResourceContainer) {
            return this.getString((ResourceContainer) entity);
        } else if (entity instanceof AssemblyContext) {
            return this.getString((AssemblyContext) entity);
        } else if (entity instanceof LinkingResource) {
            return this.getString((LinkingResource) entity);
        } else if (entity instanceof UsageSpecification) {
            return this.getString((UsageSpecification) entity);
        } else if (entity instanceof ServiceSpecification) {
            return this.getString((ServiceSpecification) entity);
        } else if (entity instanceof DatamodelAttacker) {
            return this.getString((DatamodelAttacker) entity);
        }
        return entity.getEntityName();
    }

    private String getString(final DatamodelAttacker datamodel) {
        var datatype = "";
        if (datamodel.getDataType() != null && datamodel.getDataType() instanceof Entity) {
            final var tmpEntityDatatype = (Entity) datamodel.getDataType();
            datatype = tmpEntityDatatype.getEntityName();
        }
        if (datamodel.getDataType() != null && datamodel.getDataType() instanceof PrimitiveDataType) {
            final var tmpDatatype = (PrimitiveDataType) datamodel.getDataType();
            datatype = tmpDatatype.getType() != null ? tmpDatatype.getType()
                .toString() : "INT";
        }
        final var referenceName = datamodel.getReferenceName();
        if (referenceName != null) {
            return String.format("%s:%s", referenceName, datatype);
        }
        return String.format("%s from %s:%s", datatype, datamodel.getMethod()
            .getEntityName(),
                datamodel.getMethod()
                    .getInterface__OperationSignature()
                    .getEntityName());

    }

    private String getString(final ResourceContainer entity) {
        return this.getString("ResourceContainer", entity);
    }

    private String getString(final AssemblyContext entity) {
        return this.getString("AssemblyContext", entity);
    }

    private String getString(final LinkingResource entity) {
        return this.getString("LinkingResource", entity);
    }

    private String getString(final UsageSpecification entity) {
        return String.format("%s: %s", entity.getAttribute()
            .getEntityName(),
                entity.getAttributevalue()
                    .getValues()
                    .stream()
                    .collect(Collectors.joining(", ")));
    }

    private String getString(final ServiceSpecification entity) {
        return this.getString(entity.getAssemblycontext()
            .getEntityName(), entity.getSignature());
    }

    private String getString(final String symbolName, final Entity entity) {
        return String.format("%s: %s", symbolName, entity.getEntityName());
    }

}
