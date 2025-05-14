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
