#!/bin/bash

# Java DFD Analyzer - Full Setup Script
# This script sets up the complete Java DFD Analyzer project

echo "=== Java DFD Analyzer - Full Setup ==="
echo ""

# Create all project files
mkdir -p dfd-analyzer-setup
cd dfd-analyzer-setup

# Create setup script
cat > java-dfd-analyzer.sh << 'EOF'
#!/bin/bash

# Create project structure
mkdir -p java-dfd-analyzer/{src/main/java/com/threatmodel/analyzer/{core,model,output,utils},src/test/java/com/threatmodel/analyzer}

# Create Maven pom.xml file
cat > java-dfd-analyzer/pom.xml << 'XML_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.threatmodel</groupId>
    <artifactId>java-dfd-analyzer</artifactId>
    <version>1.0-SNAPSHOT</version>

    <properties>
        <maven.compiler.source>11</maven.compiler.source>
        <maven.compiler.target>11</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>

    <dependencies>
        <!-- JavaParser for Java code parsing -->
        <dependency>
            <groupId>com.github.javaparser</groupId>
            <artifactId>javaparser-symbol-solver-core</artifactId>
            <version>3.25.5</version>
        </dependency>
        
        <!-- Jackson for JSON handling -->
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
            <version>2.15.2</version>
        </dependency>
        
        <!-- Apache Commons for various utilities -->
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-lang3</artifactId>
            <version>3.12.0</version>
        </dependency>
        
        <dependency>
            <groupId>commons-io</groupId>
            <artifactId>commons-io</artifactId>
            <version>2.13.0</version>
        </dependency>
        
        <!-- Logging -->
        <dependency>
            <groupId>org.slf4j</groupId>
            <artifactId>slf4j-api</artifactId>
            <version>2.0.7</version>
        </dependency>
        
        <dependency>
            <groupId>ch.qos.logback</groupId>
            <artifactId>logback-classic</artifactId>
            <version>1.4.11</version>
        </dependency>
        
        <!-- For parsing annotations and additional metadata -->
        <dependency>
            <groupId>org.reflections</groupId>
            <artifactId>reflections</artifactId>
            <version>0.10.2</version>
        </dependency>
        
        <!-- For command-line parsing -->
        <dependency>
            <groupId>info.picocli</groupId>
            <artifactId>picocli</artifactId>
            <version>4.7.5</version>
        </dependency>
        
        <!-- Testing -->
        <dependency>
            <groupId>org.junit.jupiter</groupId>
            <artifactId>junit-jupiter</artifactId>
            <version>5.10.0</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
    
    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>3.11.0</version>
            </plugin>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-assembly-plugin</artifactId>
                <version>3.6.0</version>
                <executions>
                    <execution>
                        <phase>package</phase>
                        <goals>
                            <goal>single</goal>
                        </goals>
                        <configuration>
                            <archive>
                                <manifest>
                                    <mainClass>com.threatmodel.analyzer.Main</mainClass>
                                </manifest>
                            </archive>
                            <descriptorRefs>
                                <descriptorRef>jar-with-dependencies</descriptorRef>
                            </descriptorRefs>
                        </configuration>
                    </execution>
                </executions>
            </plugin>
        </plugins>
    </build>
</project>
XML_EOF

# Create logback configuration
mkdir -p java-dfd-analyzer/src/main/resources
cat > java-dfd-analyzer/src/main/resources/logback.xml << 'XML_EOF'
<configuration>
    <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
            <pattern>%d{HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n</pattern>
        </encoder>
    </appender>

    <root level="info">
        <appender-ref ref="STDOUT" />
    </root>
</configuration>
XML_EOF

echo "Project structure created successfully!"
echo "Next, we'll create the Java implementation files..."

# Create directory structure for source files
mkdir -p java-dfd-analyzer/src/main/java/com/threatmodel/analyzer/core
mkdir -p java-dfd-analyzer/src/main/java/com/threatmodel/analyzer/model
mkdir -p java-dfd-analyzer/src/main/java/com/threatmodel/analyzer/output
mkdir -p java-dfd-analyzer/src/main/java/com/threatmodel/analyzer/utils

echo "Setup completed! You can now build the project by running:"
echo "  cd java-dfd-analyzer"
echo "  mvn clean package"
echo ""
echo "Or use the build-and-run.sh script to build and run the analyzer."
EOF

# Make setup script executable
chmod +x java-dfd-analyzer.sh

# Create build and run script
cat > build-and-run.sh << 'EOF'
#!/bin/bash

# Check if Maven is installed
if ! command -v mvn &> /dev/null; then
    echo "Maven is not installed. Please install Maven to build this project."
    exit 1
fi

# Set directories
PROJECT_DIR="java-dfd-analyzer"
TARGET_DIR="$PROJECT_DIR/target"
OUTPUT_DIR="dfd-output"

# Check if the project directory exists
if [ ! -d "$PROJECT_DIR" ]; then
    echo "Project directory $PROJECT_DIR does not exist. Please run the setup.sh script first."
    exit 1
fi

# Build the project
echo "Building the project..."
cd "$PROJECT_DIR" && mvn clean package

# Check if the build was successful
if [ ! -f "$TARGET_DIR/java-dfd-analyzer-1.0-SNAPSHOT-jar-with-dependencies.jar" ]; then
    echo "Build failed. Check the Maven output for errors."
    exit 1
fi

echo "Build successful."

# Create the output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Function to print usage
print_usage() {
    echo "Usage: $0 [JAVA_PROJECT_PATH]"
    echo ""
    echo "If JAVA_PROJECT_PATH is not provided, it will prompt for the path."
    echo ""
    echo "Example: $0 /path/to/java/project"
}

# Get the Java project path
if [ $# -eq 1 ]; then
    JAVA_PROJECT_PATH="$1"
else
    # Print usage
    print_usage
    
    # Prompt for the path
    echo ""
    read -p "Enter the path to the Java project to analyze: " JAVA_PROJECT_PATH
fi

# Check if the Java project path is valid
if [ ! -d "$JAVA_PROJECT_PATH" ]; then
    echo "Java project path $JAVA_PROJECT_PATH does not exist."
    exit 1
fi

# Run the application
echo "Running DFD Analyzer on $JAVA_PROJECT_PATH"
echo "Results will be saved to $OUTPUT_DIR"
echo ""

java -jar "$TARGET_DIR/java-dfd-analyzer-1.0-SNAPSHOT-jar-with-dependencies.jar" \
    --path "$JAVA_PROJECT_PATH" \
    --output "$OUTPUT_DIR" \
    --format "markdown" \
    --generate-dfd "true"

# Check if the analysis was successful
if [ $? -ne 0 ]; then
    echo "Analysis failed. Check the output for errors."
    exit 1
fi

echo ""
echo "Analysis completed successfully."
echo "Results are available in the $OUTPUT_DIR directory."
echo ""
echo "Generated files:"
ls -la "$OUTPUT_DIR"
EOF

# Make build and run script executable
chmod +x build-and-run.sh

# Create README
cat > README.md << 'EOF'
# Java DFD Analyzer

A Linux application for automatically generating Data Flow Diagrams (DFDs) from Java projects to support threat modeling.

## Overview

The Java DFD Analyzer parses a Java repository to automatically extract information about data structures, data flows, external entities, and data stores. This information is used to generate a comprehensive Data Flow Diagram that can be used as the foundation for threat modeling.

The tool analyzes Java code to identify:

1. **Data Structures**: Classes, interfaces, DTOs, entities, etc. with their fields and properties
2. **External Inputs/Outputs**: External systems, APIs, user interfaces, etc. that interact with the application
3. **Internal Processes**: Methods and functions that transform or process data
4. **Data Stores**: Databases, caches, file systems, etc. where data is persistently stored
5. **Data Flows**: The movement of data between components

## Features

- **Automatic Code Analysis**: Uses JavaParser to analyze Java source code
- **Data Structure Detection**: Identifies classes, interfaces, and their fields
- **External Entity Detection**: Identifies external systems, APIs, and interfaces
- **Process Detection**: Identifies methods that transform data
- **Data Store Detection**: Identifies databases, caches, and file systems
- **Data Flow Detection**: Identifies how data moves between components
- **Outputs in Multiple Formats**: Generates reports in markdown, HTML, CSV, and JSON
- **DFD Generation**: Creates data flow diagrams in DOT (GraphViz) and Mermaid formats
- **Sensitive Data Identification**: Flags potentially sensitive fields based on naming patterns

## Prerequisites

- Linux operating system
- Java 11 or higher
- Maven

## Installation

1. Clone or download this repository to your local machine.
2. Run the setup script to create the project structure:

```bash
chmod +x setup.sh
./setup.sh
```

3. Build the project:

```bash
cd java-dfd-analyzer
mvn clean package
```

## Usage

You can use the provided build-and-run script to simplify execution:

```bash
chmod +x build-and-run.sh
./build-and-run.sh /path/to/your/java/project
```

Or run the application directly:

```bash
java -jar java-dfd-analyzer/target/java-dfd-analyzer-1.0-SNAPSHOT-jar-with-dependencies.jar \
    --path /path/to/your/java/project \
    --output /path/to/output/directory \
    --format markdown \
    --generate-dfd true
```

### Command-Line Options

- `--path` or `-p`: Path to the Java project to analyze (required)
- `--output` or `-o`: Output directory for generated files (required)
- `--format` or `-f`: Output format (markdown, html, csv, json) - default is markdown
- `--generate-dfd`: Whether to generate DFD diagrams (true/false) - default is true

## Output Files

The analyzer generates the following output files:

- `analysis-result.md` or `.html`/`.json`/`.csv`: The main analysis report
- `data-flow-diagram.dot`: A GraphViz DOT file for the data flow diagram
- `data-flow-diagram.mmd`: A Mermaid diagram for the data flow diagram

### Visualizing the DFD

To visualize the DOT file, you can use GraphViz:

```bash
sudo apt-get install graphviz
dot -Tpng -o data-flow-diagram.png /path/to/output/directory/data-flow-diagram.dot
```

To visualize the Mermaid diagram, you can use an online Mermaid editor like [Mermaid Live Editor](https://mermaid.live/) or use a Markdown editor that supports Mermaid diagrams.

## Example Output

### Data Structure Analysis

```markdown
## Data Structures

### UserDTO

- **Type**: DTO
- **Description**: Data Transfer Object for user information
- **Source File**: /path/to/project/src/main/java/com/example/dto/UserDTO.java

#### Fields

| Field | Type | Description |
|-------|------|-------------|
| **password** [SENSITIVE] | String | User's password |
| username | String | User's login name |
| email | String | User's email address |
```

### Data Flow Diagram

```mermaid
flowchart LR
  %% External Entities
  WebClient_UserController["WebClient-UserController"] style fill:#d0e0ff,stroke:#0000ff

  %% Processes
  UserController_getUser((UserController.getUser)) style fill:#d0ffd0,stroke:#00aa00
  UserService_findById((UserService.findById)) style fill:#d0ffd0,stroke:#00aa00

  %% Data Stores
  UserRepository[(UserRepository)] style fill:#ffffd0,stroke:#aaaa00

  %% Data Flows
  WebClient_UserController -->|UserId<br>HTTP| UserController_getUser style color:#0000ff
  UserController_getUser -->|UserId| UserService_findById
  UserService_findById -->|UserId| UserRepository style color:#aa00aa,stroke-dasharray:5 5
  UserRepository -->|UserDTO| UserService_findById style color:#aa00aa,stroke-dasharray:5 5
  UserService_findById -->|UserDTO| UserController_getUser
  UserController_getUser -->|UserDTO<br>HTTP| WebClient_UserController style color:#00aa00
```

## How It Works

1. **Java Project Parsing**: The analyzer uses JavaParser to parse all Java files in the specified project
2. **Code Analysis**: It analyzes the parsed code to identify data structures, external entities, processes, and data stores
3. **Data Flow Detection**: It identifies data flows between components based on method signatures and naming patterns
4. **Report Generation**: It generates a comprehensive report in the specified format
5. **DFD Generation**: It generates data flow diagrams in DOT and Mermaid formats

## Limitations

- The analyzer relies on naming conventions and patterns to identify components, so accuracy depends on code quality
- Complex or non-standard code structures might not be identified correctly
- Dynamic runtime behavior can't be fully captured through static analysis
- The analyzer doesn't currently support multi-module Maven or Gradle projects

## Contributing

Contributions are welcome! Feel free to open issues or pull requests for any improvements or bug fixes.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
EOF

# Create a setup script that brings everything together
cat > setup.sh << 'EOF'
#!/bin/bash

echo "=== Java DFD Analyzer - Setup ==="
echo "This script will set up the Java DFD Analyzer project."
echo ""

# Run the project setup script
./java-dfd-analyzer.sh

# Set up source files
mkdir -p java-dfd-analyzer/src/main/java/com/threatmodel/analyzer

# Main class
cat > java-dfd-analyzer/src/main/java/com/threatmodel/analyzer/Main.java << 'JAVA_EOF'
package com.threatmodel.analyzer;

import java.nio.file.Path;
import java.util.concurrent.Callable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.threatmodel.analyzer.core.ProjectAnalyzer;
import com.threatmodel.analyzer.model.AnalysisResult;
import com.threatmodel.analyzer.output.DFDGenerator;
import com.threatmodel.analyzer.output.OutputGenerator;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "java-dfd-analyzer", 
         mixinStandardHelpOptions = true, 
         version = "Java DFD Analyzer 1.0",
         description = "Analyzes Java projects to create data flow diagrams for threat modeling")
public class Main implements Callable<Integer> {
    private static final Logger logger = LoggerFactory.getLogger(Main.class);

    @Option(names = {"-p", "--path"}, description = "Path to Java project root directory", required = true)
    private Path projectPath;

    @Option(names = {"-o", "--output"}, description = "Output directory for generated files", required = true)
    private Path outputPath;

    @Option(names = {"-f", "--format"}, description = "Output format (json, csv, markdown, html)", defaultValue = "markdown")
    private String outputFormat;

    @Option(names = {"--generate-dfd"}, description = "Generate Data Flow Diagram", defaultValue = "true")
    private boolean generateDfd;

    public static void main(String[] args) {
        int exitCode = new CommandLine(new Main()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() throws Exception {
        try {
            logger.info("Starting analysis of Java project at: {}", projectPath);
            
            // Analyze the project
            ProjectAnalyzer analyzer = new ProjectAnalyzer(projectPath);
            AnalysisResult result = analyzer.analyze();
            
            // Generate output
            OutputGenerator outputGenerator = new OutputGenerator(result, outputPath, outputFormat);
            outputGenerator.generate();
            
            // Generate DFD if requested
            if (generateDfd) {
                DFDGenerator dfdGenerator = new DFDGenerator(result, outputPath);
                dfdGenerator.generate();
            }
            
            logger.info("Analysis completed successfully. Results saved to: {}", outputPath);
            return 0;
        } catch (Exception e) {
            logger.error("Error during analysis", e);
            return 1;
        }
    }
}
JAVA_EOF

# Create model classes
mkdir -p java-dfd-analyzer/src/main/java/com/threatmodel/analyzer/model

# AnalysisResult.java
cat > java-dfd-analyzer/src/main/java/com/threatmodel/analyzer/model/AnalysisResult.java << 'JAVA_EOF'
package com.threatmodel.analyzer.model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents the complete analysis result of a Java project
 */
public class AnalysisResult {
    private List<DataStructure> dataStructures = new ArrayList<>();
    private List<DataFlow> dataFlows = new ArrayList<>();
    private List<ExternalEntity> externalEntities = new ArrayList<>();
    private List<Process> processes = new ArrayList<>();
    private List<DataStore> dataStores = new ArrayList<>();
    
    // Project metadata
    private String projectName;
    private String projectDescription;
    private Map<String, String> projectMetadata = new HashMap<>();

    public List<DataStructure> getDataStructures() {
        return dataStructures;
    }

    public void addDataStructure(DataStructure dataStructure) {
        this.dataStructures.add(dataStructure);
    }

    public List<DataFlow> getDataFlows() {
        return dataFlows;
    }

    public void addDataFlow(DataFlow dataFlow) {
        this.dataFlows.add(dataFlow);
    }

    public List<ExternalEntity> getExternalEntities() {
        return externalEntities;
    }

    public void addExternalEntity(ExternalEntity externalEntity) {
        this.externalEntities.add(externalEntity);
    }

    public List<Process> getProcesses() {
        return processes;
    }

    public void addProcess(Process process) {
        this.processes.add(process);
    }

    public List<DataStore> getDataStores() {
        return dataStores;
    }

    public void addDataStore(DataStore dataStore) {
        this.dataStores.add(dataStore);
    }

    public String getProjectName() {
        return projectName;
    }

    public void setProjectName(String projectName) {
        this.projectName = projectName;
    }

    public String getProjectDescription() {
        return projectDescription;
    }

    public void setProjectDescription(String projectDescription) {
        this.projectDescription = projectDescription;
    }

    public Map<String, String> getProjectMetadata() {
        return projectMetadata;
    }

    public void addProjectMetadata(String key, String value) {
        this.projectMetadata.put(key, value);
    }
    
    /**
     * Gets a summary of the analysis results
     */
    public String getSummary() {
        StringBuilder summary = new StringBuilder();
        summary.append("Project Analysis Summary for ").append(projectName).append("\n");
        summary.append("================================\n\n");
        
        summary.append("Data Structures: ").append(dataStructures.size()).append("\n");
        summary.append("Data Flows: ").append(dataFlows.size()).append("\n");
        summary.append("External Entities: ").append(externalEntities.size()).append("\n");
        summary.append("Processes: ").append(processes.size()).append("\n");
        summary.append("Data Stores: ").append(dataStores.size()).append("\n\n");
        
        return summary.toString();
    }
}
JAVA_EOF
