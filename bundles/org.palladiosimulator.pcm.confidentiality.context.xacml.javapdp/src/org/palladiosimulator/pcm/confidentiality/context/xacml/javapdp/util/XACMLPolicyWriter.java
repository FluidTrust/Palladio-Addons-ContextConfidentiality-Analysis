package org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.util;

import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import com.sun.xml.bind.v2.ContextFactory;

/**
 * The class is responsible for writing of policies to output files A separate Class is necessary
 * because of the OSGI XML-Bind implementation, which needs a custom load
 *
 * @author vladsolovyev, majuwa
 * @version 1.0.0
 */

public class XACMLPolicyWriter {

    private XACMLPolicyWriter() {
        // intentional
    }

    private static final Logger LOGGER = Logger.getLogger(XACMLPolicyWriter.class.getName());

    /**
     * Write current policies to an XACML-file
     *
     * @param outputFile
     * @param rootElement
     * @param rootClass
     */
    public static void writeXACMLFile(Path outputFile, JAXBElement<?> rootElement, Class<?> rootClass) {
        LOGGER.info(
                String.format("Transformation output will be written to %s", outputFile.toAbsolutePath().toString()));
        String msg;
        try {
            var marshaller = createMarshaller(rootClass);
            marshaller.marshal(rootElement, outputFile.toFile());
            if (Files.exists(outputFile)) {
                msg = String.format("Output file %s  written successfully",
                        outputFile.toAbsolutePath().toString());
                LOGGER.info(msg);
            } else {
                msg = String.format("Output file %s could not be written", outputFile.toAbsolutePath().toString());
                LOGGER.warning(msg);
            }
        } catch (Exception e) {
            msg = String.format("Output file %s could not be written", outputFile.toAbsolutePath().toString());
            LOGGER.log(Level.SEVERE, msg, e);
        }
    }

    private static Marshaller createMarshaller(Class<?> rootClass) throws JAXBException {
        var context = ContextFactory.createContext(new Class[] { rootClass }, null);
        var marshaller = context.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
        return marshaller;

    }

    public static Optional<String> createXMLString(JAXBElement<?> rootElement, Class<?> rootClass) {
        try {
            var marshaller = createMarshaller(rootClass);
            var stringWriter = new StringWriter();
            marshaller.marshal(rootElement, stringWriter);
            return Optional.of(stringWriter.toString());
        } catch (JAXBException e) {
            LOGGER.log(Level.SEVERE, e.getMessage());
        }
        return Optional.empty();

    }
}