package edu.kit.ipd.sdq.attacksurface.core;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackPath;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.DefaultSystemIntegration;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PCMElement;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PcmIntegrationFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.SystemIntegration;
import org.palladiosimulator.pcm.core.entity.Entity;

import edu.kit.ipd.sdq.attacksurface.graph.AttackPathSurface;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusNodeContent;
import edu.kit.ipd.sdq.attacksurface.graph.PCMElementType;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;

//TODO remove this class
public class TmpClassAttackPathGeneration {
    
    
    
    /*private void convertToAttackPath(final BlackboardWrapper board, final AttackPathSurface selectedPath,
    final PCMElement criticalPCMElement) {
if (!selectedPath.isEmpty()) {
    TODO adapt 
     * 
     *
    final AttackPath path = AttackerFactory.eINSTANCE.createAttackPath();
    path.setCriticalElement(criticalPCMElement);

    int index = 0;
    for (final var nodeContent : selectedPath) {
        if (nodeContent.isCompromised()) {
            final Entity entity = nodeContent.getContainedElement();
            final var systemIntegration = findCorrectSystemIntegration(board, entity, nodeContent.getCauseId());
            final var element = systemIntegration.getPcmelement();
            systemIntegration.setPcmelement(element);
            path.getPath().add(systemIntegration);
        } else if (index == 0) { // is attack source of attacked element
            final Entity entity = nodeContent.getContainedElement();
            final var systemIntegration = generateDefaultSystemIntegration(entity);
            path.getPath().add(systemIntegration);
        } else {
            break; // TODO: later maybe adapt for paths with gaps
        }
        index++;
    }

    //TODO add attack paths that do not succeed (s.above) (??)
    final var paths = this.changes.getAttackpaths();
    if (!contains(paths, path)) {
        paths.add(path);
        this.attackGraph.addAlreadyFoundPath(selectedPath);
    }*
}
}



/*private static boolean contains(final List<AttackPath> attackpaths, final AttackPath path) { //TODO remove asap
final var pathList = path.getPath();
final var size = pathList.size();
for (final var nowPath : attackpaths) {
    final var nowPathList = nowPath.getPath();
    if (size != nowPathList.size()) {
        continue;
    }
    boolean isContained = true;
    for (int i = 0; i < size && isContained; i++) {
        final var pcmEql = pcmElementEquals(pathList.get(i).getPcmelement(), nowPathList.get(i).getPcmelement());
        isContained = pcmEql 
                ? vulnerabilityClassAndInnerIdEquals(pathList.get(i), nowPathList.get(i))
                : false;
    }
    if (isContained) {
        return true;
    }
}
return false;
}

private static boolean vulnerabilityClassAndInnerIdEquals(SystemIntegration systemIntegration,
    SystemIntegration systemIntegrationTwo) {
return Arrays.equals(systemIntegration.getClass().getInterfaces(), 
        systemIntegration.getClass().getInterfaces())
        && Objects.equals(systemIntegration.getIdOfContent(), systemIntegrationTwo.getIdOfContent());
}

private static boolean pcmElementEquals(final PCMElement first, final PCMElement second) {
final var typeFirst = PCMElementType.typeOf(first);
final var typeSecond = PCMElementType.typeOf(second);
if (typeFirst != null && typeFirst.equals(typeSecond)) {
    return typeFirst.getEntity(first).getId().equals(typeSecond.getEntity(second).getId());
}
return false;
}*/
    
    /*protected List<AttackPathSurface> generateAllFoundAttackPaths(
    final AttackStatusNodeContent rootContent) { // TODO adapt! and generate rather in the end!                                                         // paths?
List<AttackPathSurface> allPaths = new ArrayList<>();
final var childrenOfRoot = this.attackGraph.getChildrenOfNode(rootContent);
for (final var childNode : childrenOfRoot) {
    allPaths.addAll(generateAllFoundAttackPaths(childNode));
}

/*TODO
// add compromised elements to the path
if (rootContent.isCompromised()) {
    if (allPaths.isEmpty()) {
        allPaths.add(new AttackPathSurface(new ArrayList<>(Arrays.asList(rootContent))));
    } else {
        allPaths.forEach(p -> p.add(rootContent));
    }
}

// only at the end of the recursion create the actual output attack paths
if (rootContent.equals(this.attackGraph.getRootNodeContent())) {
    for (final var path : allPaths) {
        // add the attack sources
        final var firstContent = path.get(0);
        final var childrenOfFirst = path.getNode(0).getChildNodes();
        System.out.println(firstContent + ": " + childrenOfFirst); //TODO
        for (final var childNode : childrenOfFirst) {
            final var childContent = childNode.getContent();
            if (childContent.isAttackSourceOf(firstContent)) {
                allPaths.forEach(p -> p.addFirst(childNode));
            }
        }
        
        // generate the attack paths
        final var criticalContent = root.getContent();
        final var criticalPCMElement = criticalContent.getContainedElementAsPCMElement();
        convertToAttackPath(this.modelStorage, path, criticalPCMElement);
    }
}*
return allPaths;
}*/
}
