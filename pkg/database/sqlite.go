package database

// import modernc sqlite

import (
	"database/sql"
	"log"
	"time"

	"github.com/Nathene/vulnwatch/cmd/common"
	"github.com/Nathene/vulnwatch/cmd/config"
	_ "modernc.org/sqlite"
)

// ModuleInfo stores information about a Go module
type ModuleInfo struct {
	Path        string    // Path to the module
	LastScanned time.Time // When the module was last scanned
	HashSum     string    // Hash of the go.mod file to detect changes
}

type SQLiteDatabase struct {
	*sql.DB
}

type dbConfig struct {
	driver string
	dsn    string
}

var (
	db  *SQLiteDatabase
	cfg *dbConfig
)

// Use returns the SQLiteDatabase instance to query directly on it, instead of passing around a variable.
func Use() *SQLiteDatabase {
	if db == nil {
		log.Println("Warning: Database is not initialized yet")
		// Initialize the database if it hasn't been initialized
		initDatabase()
	}
	return db
}

// newSQLiteDatabase creates a new SQLiteDatabase instance and opens the database.
func newSQLiteDatabase() *SQLiteDatabase {
	db, err := sql.Open(cfg.driver, cfg.dsn)
	if err != nil {
		log.Fatal(err)
	}
	return &SQLiteDatabase{
		DB: db,
	}
}

// initDatabase initializes the database connection and creates any required tables
func initDatabase() {
	// Set up configuration first
	cfg = &dbConfig{
		driver: config.Use().Database.Driver,
		dsn:    config.Use().Database.DSN,
	}

	// Create the database connection
	db = newSQLiteDatabase()

	// Create tables
	_, err := db.Exec("CREATE TABLE IF NOT EXISTS vulnerabilities (name TEXT, severity TEXT, directory TEXT)")
	if err != nil {
		log.Fatal(err)
	}

	// Create module_info table to track changes
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS module_info (
        path TEXT PRIMARY KEY,
        last_scanned TEXT,
        hash_sum TEXT
    )`)
	if err != nil {
		log.Fatal(err)
	}
}

func init() {
	// Call the initDatabase function to set up the database
	initDatabase()
}

// StoreVulnerability stores a vulnerability in the database
func (db *SQLiteDatabase) StoreVulnerability(vulnerability common.Vulnerability) error {
	_, err := db.Exec("INSERT INTO vulnerabilities (name, severity, directory) VALUES (?, ?, ?)", vulnerability.Name, vulnerability.Severity, vulnerability.Directory)
	if err != nil {
		return err
	}
	return nil
}

// GetVulnerabilities retrieves all vulnerabilities from the database
func (db *SQLiteDatabase) GetVulnerabilities() ([]common.Vulnerability, error) {
	rows, err := db.Query("SELECT name, severity, directory FROM vulnerabilities")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vulnerabilities []common.Vulnerability
	for rows.Next() {
		var vulnerability common.Vulnerability
		err = rows.Scan(&vulnerability.Name, &vulnerability.Severity, &vulnerability.Directory)
		if err != nil {
			return nil, err
		}
		vulnerabilities = append(vulnerabilities, vulnerability)
	}
	return vulnerabilities, nil
}

// StoreModuleInfo saves or updates a module's information in the database
func (db *SQLiteDatabase) StoreModuleInfo(info ModuleInfo) error {
	_, err := db.Exec(`
        INSERT INTO module_info (path, last_scanned, hash_sum) 
        VALUES (?, ?, ?)
        ON CONFLICT(path) DO UPDATE SET
        last_scanned = ?, 
        hash_sum = ?
    `,
		info.Path,
		info.LastScanned.Format(time.RFC3339),
		info.HashSum,
		info.LastScanned.Format(time.RFC3339),
		info.HashSum)

	if err != nil {
		return err
	}
	return nil
}

// GetModuleInfos retrieves all tracked modules from the database
func (db *SQLiteDatabase) GetModuleInfos() (map[string]ModuleInfo, error) {
	rows, err := db.Query("SELECT path, last_scanned, hash_sum FROM module_info")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	moduleInfos := make(map[string]ModuleInfo)
	for rows.Next() {
		var info ModuleInfo
		var lastScannedStr string
		err = rows.Scan(&info.Path, &lastScannedStr, &info.HashSum)
		if err != nil {
			return nil, err
		}

		// Parse the time string
		lastScanned, err := time.Parse(time.RFC3339, lastScannedStr)
		if err != nil {
			log.Printf("Error parsing time for module %s: %v, using current time", info.Path, err)
			lastScanned = time.Now()
		}
		info.LastScanned = lastScanned

		moduleInfos[info.Path] = info
	}

	return moduleInfos, nil
}

// DeleteModuleInfo removes a module's information from the database
func (db *SQLiteDatabase) DeleteModuleInfo(path string) error {
	_, err := db.Exec("DELETE FROM module_info WHERE path = ?", path)
	return err
}

// DeleteVulnerabilitiesByPath removes all vulnerabilities for a specific module path
func (db *SQLiteDatabase) DeleteVulnerabilitiesByPath(path string) error {
	_, err := db.Exec("DELETE FROM vulnerabilities WHERE directory = ?", path)
	return err
}
