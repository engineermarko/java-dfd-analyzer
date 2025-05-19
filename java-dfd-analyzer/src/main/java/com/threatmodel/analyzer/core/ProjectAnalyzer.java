package com.threatmodel.analyzer.core;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.comments.JavadocComment;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.CombinedTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.JavaParserTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver;
import com.threatmodel.analyzer.model.AnalysisResult;
import com.threatmodel.analyzer.model.DataField;
import com.threatmodel.analyzer.model.DataFlow;
import com.threatmodel.analyzer.model.DataStore;
import com.threatmodel.analyzer.model.DataStructure;
import com.threatmodel.analyzer.model.ExternalEntity;
import com.threatmodel.analyzer.model.Process;
import com.threatmodel.analyzer.utils.AnnotationExtractor;
import com.threatmodel.analyzer.utils.CommentExtractor;
import com.threatmodel.analyzer.utils.DataFlowDetector;
import com.threatmodel.analyzer.utils.ExternalEntityDetector;

/**
 * Main analyzer class for processing Java projects and extracting threat modeling information
 */
public class ProjectAnalyzer {
    private static final Logger logger = LoggerFactory.getLogger(ProjectAnalyzer.class);
    
    private final Path projectPath;
    private final JavaParser javaParser;
    private final Map<String, DataStructure> dataStructures = new HashMap<>();
    private final Map<String, Process> processes = new HashMap<>();
    private final Map<String, ExternalEntity> externalEntities = new HashMap<>();
    private final Map<String, DataStore> dataStores = new HashMap<>();
    private final List<DataFlow> dataFlows = new ArrayList<>();
    
    public ProjectAnalyzer(Path projectPath) {
        this.projectPath = projectPath;
        
        // Configure JavaParser with a symbol solver for better type resolution
        CombinedTypeSolver typeSolver = new CombinedTypeSolver();
        typeSolver.add(new ReflectionTypeSolver());
        typeSolver.add(new JavaParserTypeSolver(projectPath.toFile()));
        
        JavaSymbolSolver symbolSolver = new JavaSymbolSolver(typeSolver);
        this.javaParser = new JavaParser();
        this.javaParser.getParserConfiguration().setSymbolResolver(symbolSolver);
    }
    
    /**
     * Analyzes the Java project and returns the analysis results
     */
    public AnalysisResult analyze() throws IOException {
        logger.info("Starting project analysis at: {}", projectPath);
        
        // Find all Java files in the project
        List<Path> javaFiles = findJavaFiles(projectPath);
        logger.info("Found {} Java files to analyze", javaFiles.size());
        
        // Process each Java file
        for (Path javaFile : javaFiles) {
            try {
                processJavaFile(javaFile);
            } catch (Exception e) {
                logger.error("Error processing file: {}", javaFile, e);
            }
        }
        
        // Detect data flows between components
        detectDataFlows();
        
        // Create the analysis result
        AnalysisResult result = new AnalysisResult();
        result.setProjectName(projectPath.getFileName().toString());
        result.setProjectDescription("Analysis of " + projectPath.getFileName().toString());
        
        // Add all discovered components to the result
        dataStructures.values().forEach(result::addDataStructure);
        processes.values().forEach(result::addProcess);
        externalEntities.values().forEach(result::addExternalEntity);
        dataStores.values().forEach(result::addDataStore);
        dataFlows.forEach(result::addDataFlow);
        
        logger.info("Analysis completed: {} data structures, {} processes, {} external entities, {} data stores, {} data flows",
                dataStructures.size(), processes.size(), externalEntities.size(), dataStores.size(), dataFlows.size());
        
        return result;
    }
    
    /**
     * Recursively finds all Java files in the given directory
     */
    private List<Path> findJavaFiles(Path directory) throws IOException {
        try (Stream<Path> walk = Files.walk(directory)) {
            return walk
                    .filter(Files::isRegularFile)
                    .filter(p -> p.toString().endsWith(".java"))
                    .collect(Collectors.toList());
        }
    }
    
    /**
     * Processes a single Java file
     */
    private void processJavaFile(Path javaFile) throws IOException {
        logger.debug("Processing file: {}", javaFile);
        
        // Parse the Java file
        Optional<CompilationUnit> result = javaParser.parse(javaFile).getResult();
        if (result.isPresent()) {
            CompilationUnit cu = result.get();
            
            // Extract data structures (classes, interfaces)
            extractDataStructures(cu, javaFile);
            
            // Extract processes (methods that transform data)
            extractProcesses(cu, javaFile);
            
            // Extract external entities and API endpoints
            extractExternalEntities(cu, javaFile);
            
            // Extract data stores
            extractDataStores(cu, javaFile);
        }
    }
    
    /**
     * Extracts data structures from a compilation unit
     */
    private void extractDataStructures(CompilationUnit cu, Path javaFile) {
        cu.findAll(ClassOrInterfaceDeclaration.class).forEach(cls -> {
            String className = cls.getNameAsString();
            String qualifiedName = cls.getFullyQualifiedName().orElse(className);
            
            DataStructure dataStructure = new DataStructure(className, qualifiedName);
            dataStructure.setSourceFilePath(javaFile.toString());
            
            // Extract structure description from Javadoc
            cls.getJavadocComment().ifPresent(javadoc -> {
                dataStructure.setDescription(CommentExtractor.extractDescription(javadoc));
            });
            
            // Determine structure type based on naming, annotations, etc.
            determineDataStructureType(dataStructure, cls);
            
            // Extract fields
            cls.getFields().forEach(field -> {
                field.getVariables().forEach(var -> {
                    String fieldName = var.getNameAsString();
                    String fieldType = field.getElementType().asString();
                    
                    DataField dataField = new DataField(fieldName, fieldType);
                    
                    // Extract field description from Javadoc
                    field.getJavadocComment().ifPresent(javadoc -> {
                        dataField.setDescription(CommentExtractor.extractDescription(javadoc));
                    });
                    
                    // Extract annotations
                    AnnotationExtractor.extractAnnotations(field).forEach(dataField::addAnnotation);
                    
                    // Detect primitive or collection types
                    if (isPrimitiveType(fieldType)) {
                        dataField.setPrimitive(true);
                    }
                    
                    if (isCollectionType(fieldType)) {
                        dataField.setCollection(true);
                    }
                    
                    // Detect sensitive data based on name or annotations
                    if (isSensitiveField(dataField)) {
                        dataField.setSensitive(true);
                    }
                    
                    dataStructure.addField(dataField);
                });
            });
            
            // Add to the collection of data structures
            dataStructures.put(qualifiedName, dataStructure);
        });
    }
    
    /**
     * Extracts processes (methods) from a compilation unit
     */
    private void extractProcesses(CompilationUnit cu, Path javaFile) {
        cu.findAll(MethodDeclaration.class).forEach(method -> {
            String methodName = method.getNameAsString();
            String parentClass = method.findAncestor(ClassOrInterfaceDeclaration.class)
                    .map(cls -> cls.getFullyQualifiedName().orElse(cls.getNameAsString()))
                    .orElse("Unknown");
            
            String processId = parentClass + "." + methodName;
            String displayName = parentClass.substring(parentClass.lastIndexOf('.') + 1) + "." + methodName;
            
            Process process = new Process(processId, displayName);
            process.setSourceFilePath(javaFile.toString());
            
            // Extract process description from Javadoc
            method.getJavadocComment().ifPresent(javadoc -> {
                process.setDescription(CommentExtractor.extractDescription(javadoc));
            });
            
            // Extract input and output data structures
            extractProcessDataFlow(process, method);
            
            // Add to the collection of processes
            processes.put(processId, process);
        });
    }
    
    /**
     * Extracts external entities from a compilation unit
     */
    private void extractExternalEntities(CompilationUnit cu, Path javaFile) {
        // Use the helper class to find external entities
        ExternalEntityDetector detector = new ExternalEntityDetector();
        List<ExternalEntity> entities = detector.detectExternalEntities(cu, javaFile);
        
        // Add to the collection of external entities
        for (ExternalEntity entity : entities) {
            externalEntities.put(entity.getName(), entity);
        }
    }
    
    /**
     * Extracts data stores from a compilation unit
     */
    private void extractDataStores(CompilationUnit cu, Path javaFile) {
        // Look for database connections, file I/O, and other data storage indicators
        cu.findAll(ClassOrInterfaceDeclaration.class).forEach(cls -> {
            if (isDataStore(cls)) {
                String className = cls.getNameAsString();
                String qualifiedName = cls.getFullyQualifiedName().orElse(className);
                
                DataStore dataStore = new DataStore(qualifiedName, className);
                dataStore.setDescription("Data store identified from: " + qualifiedName);
                
                // Determine the data store type
                determineDataStoreType(dataStore, cls);
                
                // Add to the collection of data stores
                dataStores.put(qualifiedName, dataStore);
            }
        });
    }
    
    /**
     * Detects data flows between components
     */
    private void detectDataFlows() {
        // Use the helper class to detect data flows
        DataFlowDetector detector = new DataFlowDetector(
                dataStructures, processes, externalEntities, dataStores);
        
        List<DataFlow> flows = detector.detectDataFlows();
        dataFlows.addAll(flows);
    }
    
    /**
     * Determines the type of a data structure based on naming, annotations, etc.
     */
    private void determineDataStructureType(DataStructure dataStructure, ClassOrInterfaceDeclaration cls) {
        String name = cls.getNameAsString();
        
        if (cls.isInterface()) {
            dataStructure.setType(DataStructure.DataStructureType.INTERFACE);
        } else if (name.endsWith("DTO") || name.endsWith("Request") || name.endsWith("Response")) {
            dataStructure.setType(DataStructure.DataStructureType.DTO);
        } else if (name.endsWith("Entity") || cls.getAnnotationByName("Entity").isPresent()) {
            dataStructure.setType(DataStructure.DataStructureType.ENTITY);
        } else if (cls.isEnum()) {
            dataStructure.setType(DataStructure.DataStructureType.ENUM);
        } else {
            dataStructure.setType(DataStructure.DataStructureType.CLASS);
        }
        
        // Check if the class is from an external package
        String packageName = cls.getFullyQualifiedName()
                .map(fqn -> fqn.substring(0, Math.max(0, fqn.lastIndexOf('.'))))
                .orElse("");
        
        if (isExternalPackage(packageName)) {
            dataStructure.setExternal(true);
        }
    }
    
    /**
     * Extracts the input and output data structures for a process
     */
    private void extractProcessDataFlow(Process process, MethodDeclaration method) {
        // Extract input parameters
        method.getParameters().forEach(param -> {
            String paramType = param.getType().asString();
            if (dataStructures.containsKey(paramType)) {
                process.addInputDataStructureId(paramType);
            }
        });
        
        // Extract return type
        String returnType = method.getType().asString();
        if (!returnType.equals("void") && dataStructures.containsKey(returnType)) {
            process.addOutputDataStructureId(returnType);
        }
    }
    
    /**
     * Checks if a class represents a data store
     */
    private boolean isDataStore(ClassOrInterfaceDeclaration cls) {
        String className = cls.getNameAsString();
        
        // Check class name patterns
        if (className.contains("Repository") || className.contains("DAO") || 
                className.contains("Store") || className.contains("Cache")) {
            return true;
        }
        
        // Check for database-related annotations
        if (cls.getAnnotationByName("Repository").isPresent() || 
                cls.getAnnotationByName("Entity").isPresent()) {
            return true;
        }
        
        // Check fields for connection objects
        return cls.getFields().stream()
                .anyMatch(field -> {
                    String fieldType = field.getElementType().asString();
                    return fieldType.contains("Connection") || 
                           fieldType.contains("DataSource") ||
                           fieldType.contains("EntityManager");
                });
    }
    
    /**
     * Determines the type of a data store
     */
    private void determineDataStoreType(DataStore dataStore, ClassOrInterfaceDeclaration cls) {
        String className = cls.getNameAsString();
        
        if (className.contains("Database") || className.contains("Repository") || 
                className.contains("DAO")) {
            dataStore.setType(DataStore.DataStoreType.DATABASE);
        } else if (className.contains("File") || className.contains("Storage")) {
            dataStore.setType(DataStore.DataStoreType.FILE_SYSTEM);
        } else if (className.contains("Cache")) {
            dataStore.setType(DataStore.DataStoreType.CACHE);
        } else {
            dataStore.setType(DataStore.DataStoreType.OTHER);
        }
    }
    
    /**
     * Checks if a field contains sensitive information based on name or annotations
     */
    private boolean isSensitiveField(DataField field) {
        String name = field.getName().toLowerCase();
        String[] sensitivePatterns = { 
            "password", "secret", "token", "key", "credential", "ssn", 
            "social", "credit", "auth", "private", "secure" 
        };
        
        for (String pattern : sensitivePatterns) {
            if (name.contains(pattern)) {
                return true;
            }
        }
        
        // Check annotations
        return field.getAnnotations().containsKey("Sensitive") ||
               field.getAnnotations().containsKey("Secret");
    }
    
    /**
     * Checks if a type is a primitive type
     */
    private boolean isPrimitiveType(String type) {
        String[] primitives = {
            "int", "byte", "short", "long", "float", "double", "boolean", "char",
            "Integer", "Byte", "Short", "Long", "Float", "Double", "Boolean", "Character",
            "String"
        };
        
        for (String primitive : primitives) {
            if (type.equals(primitive)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Checks if a type is a collection type
     */
    private boolean isCollectionType(String type) {
        String[] collectionPatterns = {
            "List", "Set", "Map", "Collection", "Array", "[]"
        };
        
        for (String pattern : collectionPatterns) {
            if (type.contains(pattern)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Checks if a package is considered external to the project
     */
    private boolean isExternalPackage(String packageName) {
        // Common external package prefixes
        String[] externalPrefixes = {
            "java.", "javax.", "org.springframework", "com.google", "org.apache",
            "io.netty", "org.hibernate", "com.fasterxml", "org.slf4j"
        };
        
        for (String prefix : externalPrefixes) {
            if (packageName.startsWith(prefix)) {
                return true;
            }
        }
        
        return false;
    }
}
