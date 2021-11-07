package main

import (
	"fmt"
	"github.com/pkg/errors"
	"log"
	_ "net/http/pprof"
	"os"
	"path"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	uploader "uploader/src"
	"uploader/src/config"
	. "uploader/src/logging"
)

var workersChannel chan int

func openFile(p string, target **os.File) error {
	c, err := os.Open(p)
	if err != nil {
		Logger.Error("Error while reading file ", p)
		return err
	}

	*target = c

	return nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	//go func() {
	//	http.ListenAndServe("localhost:6060", nil)
	//}()

	conf := config.GetConfig()
	workersChannel = make(chan int, conf.PreprocessingThreads)

	for i := 1; i <= conf.PreprocessingThreads; i++ {
		workersChannel <- i
	}

	fpath := conf.BasePath
	identSuffix := conf.Suffix
	var err error
	fpath, err = filepath.Abs(fpath)
	if err != nil {
		Logger.Fatalln(err)
	}

	var stat os.FileInfo
	stat, err = os.Stat(fpath)
	if err != nil {
		Logger.Fatalln(err)
	} else if !stat.IsDir() {
		fpath = filepath.Dir(fpath)
	}

	summaryFiles := make([]string, 0)
	containerResultFiles := make(map[string][]string)

	filepath.Walk(fpath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			Logger.Fatalln(err)
		}

		if strings.Contains(path, "/summary.json") {
			summaryFiles = append(summaryFiles, path)
			containerResultFiles[path] = make([]string, 0)
			filepath.Walk(filepath.Dir(path), func(path2 string, info2 os.FileInfo, err2 error) error {
				if err2 != nil {
					Logger.Fatalln(err2)
				}

				if strings.Contains(path2, "/_containerResult.json") {
					containerResultFiles[path] = append(containerResultFiles[path], path2)
				}

				if strings.Contains(path2, "/_error.txt") {
					Logger.Warn(fmt.Sprintf("There were some errors %s", path2))
				}

				return nil
			})
		}

		return nil
	})

	wg := sync.WaitGroup{}
	u := uploader.NewUploader(len(summaryFiles))
	for _, summaryFile := range summaryFiles {
		workerId := <-workersChannel

		Logger.Debugf("Use preprocessing worker %d", workerId)

		dir := path.Dir(summaryFile)
		uploadData := &uploader.UploadData{}
		uploadData.ContainerResultFiles = make([]string, len(containerResultFiles[summaryFile]))

		for i, containerFile := range containerResultFiles[summaryFile] {
			uploadData.ContainerResultFiles[i] = containerFile
		}

		uploadData.JsonFile = summaryFile
		uploadData.KeylogFile = filepath.Join(dir, conf.KeyFileName)
		uploadData.PcapFile = filepath.Join(dir, conf.PcapFileName)

		if err := uploader.ParseJson(summaryFile, &uploadData.Summary); err != nil {
			Logger.Errorf(fmt.Sprintf("Error while parsing %s", summaryFile))
			continue
		}

		uploadData.Summary.Identifier += identSuffix

		fileMissing := false
		if _, err := os.Stat(uploadData.KeylogFile); errors.Is(err, os.ErrNotExist) {
			Logger.Errorf(fmt.Sprintf("Keylogfile does not exist %s", uploadData.KeylogFile))
			fileMissing = true
		}

		if _, err := os.Stat(uploadData.PcapFile); errors.Is(err, os.ErrNotExist) {
			Logger.Errorf(fmt.Sprintf("Pcap file does not exist %s", uploadData.PcapFile))
			fileMissing = true
		}

		if fileMissing {
			continue
		}

		wg.Add(1)
		go func(data *uploader.UploadData, group *sync.WaitGroup, worker int) {
			u.Upload(data)
			debug.FreeOSMemory()
			group.Done()
			workersChannel <- worker
		}(uploadData, &wg, workerId)

	}

	wg.Wait()

}
