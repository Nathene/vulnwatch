package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Nathene/vulnwatch/cmd/common"
	"github.com/Nathene/vulnwatch/cmd/config"
	"github.com/Nathene/vulnwatch/pkg/database"
	"github.com/spf13/cobra"
)

// Scanner is responsible for finding and scanning Go modules for vulnerabilities
type Scanner struct {
	// RootPath is the directory to start scanning from
	RootPath string
	// ModuleCount tracks the number of Go modules found
	ModuleCount int
	// NewModuleCount tracks the number of new or changed modules
	NewModuleCount int
	// DBMutex protects database operations
	DBMutex sync.Mutex
	// CountMutex protects the ModuleCount
	CountMutex sync.Mutex
}

// ModuleInfo stores information about a Go module
type ModuleInfo struct {
	Path        string    // Path to the module
	LastScanned time.Time // When the module was last scanned
	HashSum     string    // Hash of the go.mod file to detect changes
}

// This will be used to check all directories in the ~Documents/dev directory
// and check for vulnerabilities in the go.mod file

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan for vulnerabilities in the go.mod file",
	Run:   scan,
}

// scan is the entry point for the scan command
func scan(cmd *cobra.Command, args []string) {
	localRoot := config.Use().LocalRoot
	// Expand the tilde to the user's home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("Error getting home directory:", err)
		return
	}

	rootPath := strings.Replace(localRoot, "~", homeDir, 1)
	fmt.Println("Starting scan from:", rootPath)

	// Create a new Scanner instance
	scanner := &Scanner{
		RootPath: rootPath,
	}

	// Create a wait group to track when the walkDirectories function completes
	var wg sync.WaitGroup
	wg.Add(1)

	// Start the walkDirectories function
	go func() {
		defer wg.Done()
		if err := scanner.WalkDirectories(); err != nil {
		}
	}()

	// Wait for the function to complete
	wg.Wait()

	fmt.Println("Total Go projects found:", scanner.ModuleCount)
	fmt.Println("New or changed Go projects scanned:", scanner.NewModuleCount)

	// Print database summary
	vulnerabilities, err := database.Use().GetVulnerabilities()
	if err != nil {
		fmt.Println("Error getting vulnerabilities:", err)
		return
	}

	// Group vulnerabilities by severity
	sevCounts := make(map[string]int)
	for _, v := range vulnerabilities {
		sevCounts[v.Severity]++
	}

	fmt.Println("\nVulnerability Summary:")
	for sev, count := range sevCounts {
		fmt.Printf("  %s: %d\n", sev, count)
	}
	fmt.Printf("  Total: %d\n", len(vulnerabilities))
}

// WalkDirectories traverses the directory tree starting from the root path
// and finds all Go modules (directories containing go.mod files)
func (s *Scanner) WalkDirectories() error {
	fmt.Println("Walking directories from:", s.RootPath)

	// Get existing modules from database
	moduleInfos, err := database.Use().GetModuleInfos()
	if err != nil {
		fmt.Println("Error getting module info from database:", err)
		moduleInfos = make(map[string]database.ModuleInfo)
	}

	// Keep track of current modules to detect removed ones
	currentModules := make(map[string]bool)
	var modulesMutex sync.Mutex

	// Use filepath.WalkDir instead of filepath.Walk for better performance
	err = filepath.WalkDir(s.RootPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			fmt.Printf("Error accessing path %s: %v\n", path, err)
			return filepath.SkipDir // Skip this directory on error
		}

		// Skip hidden directories
		if d.IsDir() && strings.HasPrefix(d.Name(), ".") {
			return filepath.SkipDir // Skip hidden directories but continue traversal
		}

		// Check if there's a go.mod file in this directory
		if d.IsDir() {
			goModPath := filepath.Join(path, "go.mod")
			_, err := os.Stat(goModPath)
			if err == nil {
				// Found a go.mod file
				fmt.Println("Found Go module at:", path)

				// Mark this module as currently existing
				modulesMutex.Lock()
				currentModules[path] = true
				modulesMutex.Unlock()

				// Safely increment the total counter
				s.CountMutex.Lock()
				s.ModuleCount++
				s.CountMutex.Unlock()

				// Call scanModule to handle the scanning logic
				err := s.scanModule(path, &modulesMutex, &currentModules)
				if err != nil {
					fmt.Printf("Error scanning module %s: %v\n", path, err)
				} else {
					// Increment the new/changed counter if we scanned it
					// (scanModule only scans if new or changed)
					info, exists := moduleInfos[path]
					if !exists {
						s.CountMutex.Lock()
						s.NewModuleCount++
						s.CountMutex.Unlock()
					} else {
						// Calculate hash to check if changed
						hash, err := calculateFileHash(goModPath)
						if err != nil {
							fmt.Printf("Error calculating hash for %s: %v\n", goModPath, err)
						} else if info.HashSum != hash {
							s.CountMutex.Lock()
							s.NewModuleCount++
							s.CountMutex.Unlock()
						}
					}
				}

				// Skip further processing of this directory's children
				return filepath.SkipDir
			}
			// Continue to subdirectories
			return nil
		}

		return nil
	})

	// Handle removed modules
	for path := range moduleInfos {
		modulesMutex.Lock()
		exists := currentModules[path]
		modulesMutex.Unlock()

		if !exists {
			fmt.Printf("Module no longer exists, removing from database: %s\n", path)
			s.DBMutex.Lock()
			database.Use().DeleteModuleInfo(path)
			database.Use().DeleteVulnerabilitiesByPath(path)
			s.DBMutex.Unlock()
		}
	}

	return err
}

// calculateFileHash computes a SHA-256 hash of the file contents
func calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// RunSyftScan executes the Syft tool on a Go module directory
// and returns the scan results as a map
func (s *Scanner) RunSyftScan(modulePath string) map[string]interface{} {
	fmt.Println("Generating SBOM with Syft for:", modulePath)

	// Create a temporary file to store the SBOM
	tmpFile, err := os.CreateTemp("", "syft-sbom-*.json")
	if err != nil {
		fmt.Println("Error creating temp file:", err)
		return map[string]interface{}{
			"path":      modulePath,
			"timestamp": time.Now(),
			"error":     err.Error(),
		}
	}
	tmpFile.Close()
	sbomPath := tmpFile.Name()
	// Note: We're not deferring the removal here anymore
	// The file will be removed after Grype uses it

	// Run Syft command to generate SBOM in JSON format
	cmd := exec.Command("syft", "packages", modulePath, "-o", "json", "--file", sbomPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Error running Syft:", err)
		fmt.Println("Syft output:", string(output))
		os.Remove(sbomPath) // Clean up on error
		return map[string]interface{}{
			"path":      modulePath,
			"timestamp": time.Now(),
			"error":     err.Error(),
		}
	}

	// Read the SBOM from the file
	sbomData, err := os.ReadFile(sbomPath)
	if err != nil {
		fmt.Println("Error reading SBOM file:", err)
		os.Remove(sbomPath) // Clean up on error
		return map[string]interface{}{
			"path":      modulePath,
			"timestamp": time.Now(),
			"error":     err.Error(),
		}
	}

	// Parse the JSON output into a map
	var scanResults map[string]interface{}
	err = json.Unmarshal(sbomData, &scanResults)
	if err != nil {
		fmt.Println("Error unmarshalling Syft output:", err)
		os.Remove(sbomPath) // Clean up on error
		return map[string]interface{}{
			"path":      modulePath,
			"timestamp": time.Now(),
			"error":     err.Error(),
		}
	}

	// Add metadata to the scan results
	scanResults["path"] = modulePath
	scanResults["timestamp"] = time.Now()
	scanResults["sbom_file"] = sbomPath // Store the path to use with Grype

	return scanResults
}

// RunGrypeScan executes Grype to find vulnerabilities using Syft's SBOM
// and returns the vulnerabilities found
func (s *Scanner) RunGrypeScan(modulePath string, sbomResults map[string]interface{}) map[string]interface{} {
	sbomFile, ok := sbomResults["sbom_file"].(string)
	if !ok || sbomFile == "" {
		fmt.Println("No SBOM file path found in results")
		return nil
	}

	fmt.Println("Scanning for vulnerabilities with Grype in:", modulePath)

	// Create a temporary file to store Grype results
	tmpFile, err := os.CreateTemp("", "grype-results-*.json")
	if err != nil {
		fmt.Println("Error creating temp file for Grype:", err)
		os.Remove(sbomFile) // Clean up the SBOM file if we can't proceed with Grype
		return nil
	}
	tmpFile.Close()
	grypePath := tmpFile.Name()

	// Run Grype command on the SBOM file
	cmd := exec.Command("grype", "sbom:"+sbomFile, "-o", "json", "--file", grypePath)
	output, err := cmd.CombinedOutput()

	// Clean up the SBOM file since we no longer need it
	os.Remove(sbomFile)

	if err != nil {
		fmt.Println("Error running Grype:", err)
		fmt.Println("Grype output:", string(output))
		os.Remove(grypePath) // Clean up the Grype results file on error
		return nil
	}

	// Read the Grype results from the file
	grypeData, err := os.ReadFile(grypePath)

	// Clean up the Grype results file as we've read it into memory
	os.Remove(grypePath)

	if err != nil {
		fmt.Println("Error reading Grype results file:", err)
		return nil
	}

	// Parse the JSON output into a map
	var vulnerabilities map[string]interface{}
	err = json.Unmarshal(grypeData, &vulnerabilities)
	if err != nil {
		fmt.Println("Error unmarshalling Grype output:", err)
		return nil
	}

	return vulnerabilities
}

// StoreInDatabase saves the scan results to a database
// This extracts relevant package information from Syft's SBOM output
// and vulnerability information from Grype
func (s *Scanner) StoreInDatabase(modulePath string, sbomResults map[string]interface{}, vulnerabilityResults map[string]interface{}) {
	fmt.Println("Storing scan results for:", modulePath)

	// First, clear existing vulnerabilities for this path
	err := database.Use().DeleteVulnerabilitiesByPath(modulePath)
	if err != nil {
		fmt.Printf("Error clearing existing vulnerabilities for %s: %v\n", modulePath, err)
	}

	// If we have vulnerability results from Grype, process them
	if vulnerabilityResults != nil {
		s.processGrypeResults(modulePath, vulnerabilityResults)
		return
	}

	// If no Grype results, fall back to processing just the SBOM data
	// s.processSyftResults(modulePath, sbomResults)
}

// processGrypeResults processes and stores vulnerability data from Grype
func (s *Scanner) processGrypeResults(modulePath string, vulnerabilityResults map[string]interface{}) {
	// Check if matches exist in the vulnerability results
	matches, ok := vulnerabilityResults["matches"].([]interface{})
	if !ok || len(matches) == 0 {
		fmt.Println("No vulnerabilities found in:", modulePath)
		return
	}

	fmt.Printf("Found %d vulnerabilities in %s\n", len(matches), modulePath)

	// Process each vulnerability match
	for _, matchVal := range matches {
		match, ok := matchVal.(map[string]interface{})
		if !ok {
			continue
		}

		// Extract vulnerability details
		var vuln map[string]interface{}
		var artifact map[string]interface{}

		if v, ok := match["vulnerability"].(map[string]interface{}); ok {
			vuln = v
		} else {
			continue
		}

		if a, ok := match["artifact"].(map[string]interface{}); ok {
			artifact = a
		} else {
			continue
		}

		// Extract relevant information
		vulnID := getStringValue(vuln, "id", "unknown-id")
		severity := getStringValue(vuln, "severity", "unknown")
		packageName := getStringValue(artifact, "name", "unknown-package")
		packageVersion := getStringValue(artifact, "version", "")

		// Create a descriptive name
		name := vulnID + " in " + packageName
		if packageVersion != "" {
			name += "@" + packageVersion
		}

		// Store in database
		err := database.Use().StoreVulnerability(common.Vulnerability{
			Name:      name,
			Severity:  severity,
			Directory: modulePath,
		})

		if err != nil {
			fmt.Printf("Error storing vulnerability for %s: %v\n", name, err)
		} else {
			fmt.Printf("Stored vulnerability: %s with severity %s\n", name, severity)
		}
	}
}

// processSyftResults processes and stores package information from Syft
func (s *Scanner) processSyftResults(modulePath string, sbomResults map[string]interface{}) {
	// Get the artifacts array from the scan results
	var artifacts []interface{}

	// Check if artifacts exists in the scan results
	if artifactsVal, ok := sbomResults["artifacts"]; ok && artifactsVal != nil {
		// Try to cast to an array of interfaces
		if artifactsArr, ok := artifactsVal.([]interface{}); ok {
			artifacts = artifactsArr
		}
	}

	// If no artifacts were found, store a basic entry
	if len(artifacts) == 0 {
		err := database.Use().StoreVulnerability(common.Vulnerability{
			Name:      filepath.Base(modulePath),
			Severity:  "unknown",
			Directory: modulePath,
		})

		if err != nil {
			fmt.Printf("Error storing vulnerability for %s: %v\n", modulePath, err)
		}
		return
	}

	// Process each artifact/package found by Syft
	for _, artifactVal := range artifacts {
		// Try to cast the artifact to a map
		artifact, ok := artifactVal.(map[string]interface{})
		if !ok {
			continue
		}

		// Extract package information
		packageName := getStringValue(artifact, "name", "")
		if packageName == "" {
			continue
		}

		packageVersion := getStringValue(artifact, "version", "")
		packageType := getStringValue(artifact, "type", "")

		// For packages with no vulnerabilities, we'll just use info level
		severity := "info"
		if packageType != "" {
			severity = "package-type:" + packageType
		}

		// Create a descriptive name from package name and version
		name := packageName
		if packageVersion != "" {
			name = packageName + "@" + packageVersion
		}

		// Store in database
		err := database.Use().StoreVulnerability(common.Vulnerability{
			Name:      name,
			Severity:  severity,
			Directory: modulePath,
		})

		if err != nil {
			fmt.Printf("Error storing package info for %s: %v\n", name, err)
		} else {
			fmt.Printf("Stored package info: %s with type %s\n", name, packageType)
		}
	}
}

// Helper function to safely extract string values from maps
func getStringValue(data map[string]interface{}, key string, defaultValue string) string {
	if val, ok := data[key]; ok && val != nil {
		if strVal, ok := val.(string); ok {
			return strVal
		}
	}
	return defaultValue
}

// Update the existing scanModule function
func (s *Scanner) scanModule(path string, pathsToModulesMutex *sync.Mutex, pathsToModules *map[string]bool) error {
	// Calculate the hash of the go.mod file
	goModPath := filepath.Join(path, "go.mod")
	hashSum, err := calculateFileHash(goModPath)
	if err != nil {
		return fmt.Errorf("failed to calculate hash for %s: %w", goModPath, err)
	}

	// Check if the module has already been scanned and hasn't changed
	db := database.Use()
	moduleInfos, err := db.GetModuleInfos()
	if err != nil {
		return fmt.Errorf("failed to get module infos from database: %w", err)
	}

	moduleInfo, exists := moduleInfos[path]
	if exists && moduleInfo.HashSum == hashSum {
		// Module hasn't changed, skip scanning
		log.Printf("Module at %s hasn't changed since last scan, skipping...", path)
		return nil
	}

	// Process this Go module with Syft to generate SBOM
	sbomResults := s.RunSyftScan(path)

	// Process the SBOM with Grype to find vulnerabilities
	vulnerabilities := s.RunGrypeScan(path, sbomResults)

	// Safely store the results in the database
	s.DBMutex.Lock()
	s.StoreInDatabase(path, sbomResults, vulnerabilities)

	// Update or create module info in database
	newModuleInfo := database.ModuleInfo{
		Path:        path,
		LastScanned: time.Now(),
		HashSum:     hashSum,
	}

	err = db.StoreModuleInfo(newModuleInfo)
	if err != nil {
		s.DBMutex.Unlock()
		return fmt.Errorf("failed to store module info for %s: %w", path, err)
	}
	s.DBMutex.Unlock()

	return nil
}
