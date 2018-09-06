package dumper

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

var dump *os.File
var count int

func dumpFile(path string) error {
	log.Printf("Reading '%v'", path)
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer reader.Close()
	decoder := json.NewDecoder(reader)
	var items map[string]interface{}
	err = decoder.Decode(&items)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(dump)
	encoder.SetIndent("", "  ")
	return encoder.Encode(items)
}

func logWalk(path string, info os.FileInfo, err error) error {
	if info.IsDir() {
		return nil
	}
	err = dumpFile(path)
	if err != nil {
		log.Println(err)
	} else {
		count++
	}
	return nil
}

// DumpLogs reads all events from folder and dumps them to outfile
func DumpLogs(folder string, outfile string) error {
	if folder == "" {
		return fmt.Errorf("Logs folder must be specified")
	}
	var err error
	dump, err = os.Create(outfile)
	if err != nil {
		return err
	}
	defer dump.Close()
	filepath.Walk(folder, logWalk)
	log.Printf("%v log files from '%v' saved to '%v'", count, folder, outfile)
	return nil
}
