package main

import (
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

var workers chan int

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
	workers = make(chan int, conf.PreprocessingThreads)

	for i := 1; i <= conf.PreprocessingThreads; i++ {
		workers <- i
	}

	fpath := conf.BasePath
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

	files := make([]string, 0)
	filepath.Walk(fpath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			Logger.Fatalln(err)
		}

		if strings.Contains(path, "/testResults.json") {
			files = append(files, path)
		}

		return nil
	})

	wg := sync.WaitGroup{}
	u := uploader.NewUploader(len(files))
	for _, v := range files {
		workerId := <- workers

		Logger.Debugf("Use preprocessing worker %d", workerId)

		dir := path.Dir(v)
		uploadData := &uploader.UploadData{}

		if err = openFile(v, &uploadData.JsonFile); err != nil {
			continue
		}

		if err = openFile(filepath.Join(dir, "keyfile.log"), &uploadData.KeylogFile); err != nil {
			continue
		}

		if err = openFile(filepath.Join(dir, "dump.pcap"), &uploadData.PcapFile); err != nil {
			continue
		}

		uploadData.Identifier = path.Base(dir)

		wg.Add(1)
		go func(data *uploader.UploadData, group *sync.WaitGroup, worker int) {
			u.Upload(data)
			debug.FreeOSMemory()
			group.Done()
			workers <- worker
		}(uploadData, &wg, workerId)

	}

	wg.Wait()

	//select {
	//
	//}

}
