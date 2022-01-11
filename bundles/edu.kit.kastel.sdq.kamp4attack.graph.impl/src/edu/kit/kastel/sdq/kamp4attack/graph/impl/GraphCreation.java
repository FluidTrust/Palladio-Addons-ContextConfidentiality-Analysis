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
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceRestriction;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.repository.PrimitiveDataType;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import com.google.common.graph.MutableValueGraph;
import com.google.common.graph.ValueGraphBuilder;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.AbstractKAMP4attackModificationRepository;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ModifyEntity;
import edu.kit.kastel.sdq.kamp4attack.graph.api.AttackGraphCreation;
import edu.kit.kastel.sdq.kamp4attack.graph.impl.output.DotCreation;

@Component(service = AttackGraphCreation.class)
public class GraphCreation implements AttackGraphCreation {

    private final Logger logger = Logger.getLogger(GraphCreation.class);

    @Override
    public Optional<Path> createAttackGraph(AbstractKAMP4attackModificationRepository<?> modificationPartition) {
        if (modificationPartition.getChangePropagationSteps().size() == 1) {

            var change = (CredentialChange) modificationPartition.getChangePropagationSteps().get(0);

            MutableValueGraph<String, String> graph = ValueGraphBuilder.directed().allowsSelfLoops(true).build();

            fillGraph(graph, change.getCompromisedassembly());
            fillGraph(graph, change.getCompromisedresource());
            fillGraph(graph, change.getCompromisedlinkingresource());
            fillGraph(graph, change.getCompromisedservice());
            fillGraph(graph, change.getContextchange());
            fillGraph(graph, change.getCompromiseddata());
            var dot = new DotCreation();
            var dotString = dot.createOutputFormat(graph);

            try {
                var file = Files.createTempFile("test", ".dot");

                Files.writeString(file.toAbsolutePath(), dotString);
                var command = String.format("dot -Tpng %s", file.toAbsolutePath().toString());
                var process = Runtime.getRuntime().exec(command);

                var outputFile = Files.createTempFile("test", ".png");
                var outputStream = Files.newOutputStream(outputFile.toAbsolutePath());
                process.getInputStream().transferTo(outputStream);

                var errorStream = new ByteArrayOutputStream();
                process.getErrorStream().transferTo(errorStream);
                if (errorStream.size() != 0) {
                    this.logger.error(errorStream.toString());
                }
                return Optional.of(outputFile);
            } catch (IOException e) {
                this.logger.error(e);
            }

        }
        return Optional.empty();

    }

    private void fillGraph(MutableValueGraph<String, String> graph,
            List<? extends ModifyEntity<? extends Entity>> change) {
        for (var assembly : change) {
            var node = assembly.getAffectedElement();
            var source = getSource(assembly.getCausingElements());
            for (var entity : source) {
                graph.putEdgeValue(entity, getString(node), getName(assembly.getCausingElements()));
            }
        }
    }

    private List<String> getSource(List<EObject> list) {
        return list.stream()
                .filter(e -> (e instanceof ResourceContainer) || e instanceof AssemblyContext
                        || e instanceof LinkingResource || e instanceof MethodSpecification)
                .map(Entity.class::cast).map(this::getString).collect(Collectors.toList());
    }

    private List<Vulnerability> getVulnerabilites(List<EObject> list) {
        return list.stream().filter(Vulnerability.class::isInstance).map(Vulnerability.class::cast)
                .collect(Collectors.toList());
    }

    private List<UsageSpecification> getCredentials(List<EObject> list) {
        return list.stream().filter(UsageSpecification.class::isInstance).map(UsageSpecification.class::cast)
                .collect(Collectors.toList());
    }

    private String getName(List<EObject> list) {
        var vulnerabilitiesString = getVulnerabilites(list).stream().map(Entity::getEntityName).collect(Collectors.joining(", "));
        var credentials = getCredentials(list).stream().map(this::getString).collect(Collectors.joining(", "));

        if (vulnerabilitiesString.isEmpty() && credentials.isEmpty()) {
            return "implicit";
        } else if (vulnerabilitiesString.isEmpty()) {
            return credentials;
        }else if(credentials.isEmpty()) {
            return vulnerabilitiesString;
        }
        return String.join(", ", vulnerabilitiesString, credentials);

    }

    private String getString(Entity entity) {
        if (entity instanceof ResourceContainer) {
            return getString((ResourceContainer) entity);
        } else if (entity instanceof AssemblyContext) {
            return getString((AssemblyContext) entity);
        } else if (entity instanceof LinkingResource) {
            return getString((LinkingResource) entity);
        } else if (entity instanceof UsageSpecification) {
            return getString((UsageSpecification) entity);
        }
        else if (entity instanceof ServiceRestriction) {
            return getString((ServiceRestriction) entity);
        }
        else if (entity instanceof DatamodelAttacker) {
            return getString((DatamodelAttacker) entity);
        }
        return entity.getEntityName();
    }

    private String getString(DatamodelAttacker datamodel) {
        var datatype = "";
        if (datamodel.getDataType() != null && datamodel.getDataType() instanceof Entity) {
            var tmpEntityDatatype = (Entity) datamodel.getDataType();
            datatype = tmpEntityDatatype.getEntityName();
        }
        if (datamodel.getDataType() != null && datamodel.getDataType() instanceof PrimitiveDataType) {
            var tmpDatatype = (PrimitiveDataType) datamodel.getDataType();
            datatype = tmpDatatype.getType() != null ? tmpDatatype.getType().toString() : "INT";
        }
        var referenceName = datamodel.getReferenceName();
        if (referenceName != null) {
            return String.format("%s:%s", referenceName, datatype);
        }
        return String.format("%s from %s:%s", datatype, datamodel.getMethod().getEntityName(),
                datamodel.getMethod().getInterface__OperationSignature().getEntityName());

    }
    private String getString(ResourceContainer entity) {
        return getString("ResourceContainer", entity);
    }

    private String getString(AssemblyContext entity) {
        return getString("AssemblyContext", entity);
    }

    private String getString(LinkingResource entity) {
        return getString("LinkingResource", entity);
    }

    private String getString(UsageSpecification entity) {
        return String.format("%s: %s", entity.getAttribute().getEntityName(),
                entity.getAttributevalue().getValues().stream().collect(Collectors.joining(", ")));
    }

    private String getString(ServiceRestriction entity) {
        return getString(entity.getAssemblycontext().getEntityName(), entity.getSignature());
    }

    private String getString(String symbolName, Entity entity) {
        return String.format("%s: %s", symbolName, entity.getEntityName());
    }

}
