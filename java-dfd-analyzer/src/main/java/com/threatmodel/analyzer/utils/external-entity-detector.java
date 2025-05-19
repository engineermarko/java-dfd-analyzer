package com.threatmodel.analyzer.utils;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.threatmodel.analyzer.model.ExternalEntity;
import com.threatmodel.analyzer.model.ExternalEntity.ExternalEntityType;

/**
 * Utility class for detecting external entities based on code patterns
 */
public class ExternalEntityDetector {
    
    /**
     * Detects external entities from a compilation unit
     * 
     * @param cu The compilation unit to analyze
     * @param javaFile The source file being analyzed
     * @return A list of detected external entities
     */
    public static List<ExternalEntity> detectExternalEntities(CompilationUnit cu, Path javaFile) {
        List<ExternalEntity> entities = new ArrayList<>();
        
        // Look for REST controllers and API endpoints
        detectRestControllers(cu, entities);
        
        // Look for database connections
        detectDatabaseConnections(cu, entities);
        
        // Look for external service clients
        detectServiceClients(cu, entities);
        
        return entities;
    }
    
    /**
     * Detects REST controllers and API endpoints
     */
    private static void detectRestControllers(CompilationUnit cu, List<ExternalEntity> entities) {
        cu.findAll(ClassOrInterfaceDeclaration.class).forEach(cls -> {
            // Check for Spring RestController/Controller annotations
            boolean isRestController = cls.getAnnotations().stream()
                    .anyMatch(a -> a.getNameAsString().contains("RestController") || 
                                  a.getNameAsString().contains("Controller"));
            
            if (isRestController) {
                // Extract the base path from RequestMapping if available
                String basePath = extractRequestMappingPath(cls);
                String entityName = "WebClient-" + cls.getNameAsString();
                
                ExternalEntity entity = new ExternalEntity(entityName);
                entity.setDescription("Web client accessing REST endpoints in " + cls.getNameAsString());
                entity.setType(ExternalEntityType.USER);
                entity.addProtocol("HTTP/HTTPS");
                
                if (basePath != null && !basePath.isEmpty()) {
                    entity.addMetadata("basePath", basePath);
                }
                
                entities.add(entity);
                
                // Extract individual endpoints
                cls.findAll(MethodDeclaration.class).forEach(method -> {
                    method.getAnnotations().stream()
                            .filter(a -> a.getNameAsString().contains("Mapping"))
                            .findFirst()
                            .ifPresent(mapping -> {
                                String endpointPath = extractMappingPath(mapping);
                                if (endpointPath != null && !endpointPath.isEmpty()) {
                                    String fullPath = (basePath != null ? basePath : "") + endpointPath;
                                    entity.addMetadata("endpoint-" + method.getNameAsString(), fullPath);
                                }
                            });
                });
            }
        });
    }
    
    /**
     * Detects database connections
     */
    private static void detectDatabaseConnections(CompilationUnit cu, List<ExternalEntity> entities) {
        cu.findAll(ClassOrInterfaceDeclaration.class).forEach(cls -> {
            // Check for repository classes
            boolean isRepository = cls.getAnnotations().stream()
                    .anyMatch(a -> a.getNameAsString().contains("Repository")) ||
                    cls.getNameAsString().contains("Repository") ||
                    cls.getNameAsString().contains("DAO");
            
            if (isRepository) {
                String entityName = "Database-" + cls.getNameAsString();
                
                ExternalEntity entity = new ExternalEntity(entityName);
                entity.setDescription("Database accessed by " + cls.getNameAsString());
                entity.setType(ExternalEntityType.DATABASE);
                entity.addProtocol("JDBC/SQL");
                
                entities.add(entity);
            }
        });
    }
    
    /**
     * Detects external service clients
     */
    private static void detectServiceClients(CompilationUnit cu, List<ExternalEntity> entities) {
        cu.findAll(ClassOrInterfaceDeclaration.class).forEach(cls -> {
            // Check for service clients
            boolean isServiceClient = cls.getAnnotations().stream()
                    .anyMatch(a -> a.getNameAsString().contains("FeignClient") || 
                                  a.getNameAsString().contains("Service")) ||
                    cls.getNameAsString().contains("Client") ||
                    cls.getNameAsString().contains("Service");
            
            if (isServiceClient) {
                String entityName = "Service-" + cls.getNameAsString();
                
                ExternalEntity entity = new ExternalEntity(entityName);
                entity.setDescription("External service accessed by " + cls.getNameAsString());
                entity.setType(ExternalEntityType.SERVICE);
                
                // Try to determine the protocol
                if (cls.getNameAsString().contains("Rest")) {
                    entity.addProtocol("HTTP/HTTPS");
                } else if (cls.getNameAsString().contains("Soap")) {
                    entity.addProtocol("SOAP");
                } else if (cls.getNameAsString().contains("Kafka")) {
                    entity.addProtocol("Kafka");
                } else if (cls.getNameAsString().contains("Jms")) {
                    entity.addProtocol("JMS");
                } else {
                    entity.addProtocol("Unknown");
                }
                
                entities.add(entity);
            }
        });
    }
    
    /**
     * Extracts the path from a RequestMapping annotation
     */
    private static String extractRequestMappingPath(ClassOrInterfaceDeclaration cls) {
        return cls.getAnnotations().stream()
                .filter(a -> a.getNameAsString().contains("RequestMapping"))
                .findFirst()
                .map(ExternalEntityDetector::extractMappingPath)
                .orElse("");
    }
    
    /**
     * Extracts the path from a mapping annotation
     */
    private static String extractMappingPath(AnnotationExpr annotation) {
        if (annotation.isSingleMemberAnnotationExpr()) {
            return annotation.asSingleMemberAnnotationExpr().getMemberValue().toString().replaceAll("\"", "");
        } else if (annotation.isNormalAnnotationExpr()) {
            return annotation.asNormalAnnotationExpr().getPairs().stream()
                    .filter(p -> p.getNameAsString().equals("path") || p.getNameAsString().equals("value"))
                    .findFirst()
                    .map(p -> p.getValue().toString().replaceAll("\"", ""))
                    .orElse("");
        }
        return "";
    }
}
