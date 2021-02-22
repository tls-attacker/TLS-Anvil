package config

import (
	"flag"
	"fmt"
	"os"
)

var conf *Config

type Config struct {
	DatabaseUrl string
	PreprocessingThreads int
	BasePath string
}

func GetConfig() *Config {
	if conf == nil {
		conf = &Config{}
		conf.parse()
	}
	return conf
}

func (c *Config) parse() {
	if flag.Parsed() {
		return
	}

	flag.StringVar(&conf.DatabaseUrl, "db", "localhost:27017", "URL where the database is available at")
	flag.StringVar(&conf.BasePath, "path", "", "Scans path recurively for test results")
	flag.IntVar(&conf.PreprocessingThreads, "n", 5, "Preprocessing threads")

	flag.Parse()

	if conf.BasePath == "" {
		fmt.Println("flag -path is required")
		flag.PrintDefaults()
		os.Exit(2)
	}

	return
}
